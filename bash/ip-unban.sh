#!/usr/bin/env bash
# Remove an IP ban from Fail2ban and/or nftables sets.
# Finds where the IP is actually banned, asks confirmation, removes, re-verifies.
# To inspect without removing, use ip-ban-check.sh.

set -u

PROGRAM=${0##*/}
IP=''
JAIL=''
NFT_FAMILY=''
NFT_TABLE=''
NFT_CHAIN=''
NFT_SET=''
USE_SUDO=0
ASSUME_YES=0
declare -a IGNORE_JAILS=()
declare -a IGNORE_SETS=()
declare -a BAN_JAILS=()
declare -a BAN_SETS=()
RULE_MATCH=0

usage() {
    cat <<EOF
Usage: $PROGRAM --ip ADDRESS [options]

  --ip ADDRESS             IPv4 or IPv6 address to unban (required)
  --jail NAME              Only unban this Fail2ban jail
  --ignore-jail NAME       Skip Fail2ban jail (repeatable)
  --family FAMILY          Limit nftables search (inet, ip, ip6, ...)
  --table TABLE            Limit nftables search to table
  --chain CHAIN            Limit nftables search to chain
  --set SET                Limit nftables search to set
  --ignore-set SET         Skip nftables set (repeatable)
  --yes                    Do not ask for confirmation
  --sudo                   Run fail2ban-client and nft through sudo
  -h, --help               Show this help

Exit codes: 0 IP unbanned (or was not banned), 1 removal failed/partial, 2 error.

Examples:
  $PROGRAM --ip 203.0.113.7
  $PROGRAM --ip 2001:db8::7 --family inet --table filter --set blacklist --yes
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 2
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

valid_ip() {
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$IP" <<'PY'
import ipaddress
import sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
PY
        return $?
    fi

    [[ $IP != *[\;\{\}\|\&\`\$\(\)\<\>]* && $IP =~ ^[0-9A-Fa-f:.]+$ ]]
}

run_privileged() {
    if (( USE_SUDO )); then
        sudo "$@"
    else
        "$@"
    fi
}

contains_ip() {
    local line=$1
    local needle=${IP//./\\.}
    [[ $line =~ (^|[[:space:]{,])$needle([[:space:]},;]|$) ]]
}

is_ignored() {
    local value=$1 ignored
    shift
    for ignored in "$@"; do
        [[ $value == "$ignored" ]] && return 0
    done
    return 1
}

find_fail2ban() {
    local jail_list jail jail_status banned

    need_command fail2ban-client
    jail_list=$(run_privileged fail2ban-client status 2>/dev/null |
        sed -n 's/.*Jail list:[[:space:]]*//p') || {
        printf 'Fail2ban: unable to read jail list\n' >&2
        return 1
    }

    if [[ -n $JAIL ]]; then
        jail_list=$JAIL
    elif [[ -z $jail_list ]]; then
        return 0
    fi

    BAN_JAILS=()
    IFS=',' read -ra jail_names <<< "$jail_list"
    for jail in "${jail_names[@]}"; do
        jail=${jail//[[:space:]]/}
        [[ -n $jail ]] || continue
        is_ignored "$jail" "${IGNORE_JAILS[@]}" && continue
        jail_status=$(run_privileged fail2ban-client status "$jail" 2>/dev/null) || continue
        banned=$(sed -n 's/.*Banned IP list:[[:space:]]*//p' <<< "$jail_status")
        [[ " $banned " == *" $IP "* ]] && BAN_JAILS+=("$jail")
    done
}

find_nft() {
    local rules line family table chain set key

    need_command nft
    rules=$(run_privileged nft -a list ruleset 2>/dev/null) || {
        printf 'nftables: unable to read ruleset\n' >&2
        return 1
    }

    BAN_SETS=()
    RULE_MATCH=0
    family=''; table=''; chain=''; set=''
    while IFS= read -r line; do
        if [[ $line =~ ^table[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]*\{ ]]; then
            family=${BASH_REMATCH[1]}; table=${BASH_REMATCH[2]}; chain=''; set=''
        elif [[ $line =~ ^[[:space:]]*chain[[:space:]]+([^[:space:]]+)[[:space:]]*\{ ]]; then
            chain=${BASH_REMATCH[1]}; set=''
        elif [[ $line =~ ^[[:space:]]*set[[:space:]]+([^[:space:]]+)[[:space:]]*\{ ]]; then
            set=${BASH_REMATCH[1]}
        elif [[ $line =~ ^[[:space:]]*\} ]]; then
            set=''
        fi

        [[ -n $NFT_FAMILY && $family != "$NFT_FAMILY" ]] && continue
        [[ -n $NFT_TABLE && $table != "$NFT_TABLE" ]] && continue
        [[ -n $NFT_CHAIN && $chain != "$NFT_CHAIN" ]] && continue
        [[ -n $NFT_SET && $set != "$NFT_SET" ]] && continue
        [[ -n $set ]] && is_ignored "$set" "${IGNORE_SETS[@]}" && continue

        contains_ip "$line" || continue
        if [[ -n $set ]]; then
            key="$family|$table|$set"
            [[ " ${BAN_SETS[*]-} " == *" $key "* ]] || BAN_SETS+=("$key")
        else
            RULE_MATCH=1
        fi
    done <<< "$rules"
}

verify_gone() {
    local left=0
    find_fail2ban && (( ${#BAN_JAILS[@]} )) && left=1
    find_nft && { (( ${#BAN_SETS[@]} )) || (( RULE_MATCH )); } && left=1
    if (( left )); then
        printf 'WARNING: IP still present after unban:\n' >&2
        for jail in "${BAN_JAILS[@]+"${BAN_JAILS[@]}"}"; do printf '  fail2ban jail=%s\n' "$jail" >&2; done
        for key in "${BAN_SETS[@]+"${BAN_SETS[@]}"}"; do printf '  nftables %s\n' "${key//|/ }" >&2; done
        return 1
    fi
    printf 'Verified: %s no longer banned\n' "$IP"
}

while (($#)); do
    case $1 in
        --ip) [[ $# -ge 2 ]] || die "--ip needs value"; IP=$2; shift 2 ;;
        --jail) [[ $# -ge 2 ]] || die "--jail needs value"; JAIL=$2; shift 2 ;;
        --ignore-jail) [[ $# -ge 2 ]] || die "--ignore-jail needs value"; IGNORE_JAILS+=("$2"); shift 2 ;;
        --family) [[ $# -ge 2 ]] || die "--family needs value"; NFT_FAMILY=$2; shift 2 ;;
        --table) [[ $# -ge 2 ]] || die "--table needs value"; NFT_TABLE=$2; shift 2 ;;
        --chain) [[ $# -ge 2 ]] || die "--chain needs value"; NFT_CHAIN=$2; shift 2 ;;
        --set) [[ $# -ge 2 ]] || die "--set needs value"; NFT_SET=$2; shift 2 ;;
        --ignore-set) [[ $# -ge 2 ]] || die "--ignore-set needs value"; IGNORE_SETS+=("$2"); shift 2 ;;
        --yes) ASSUME_YES=1; shift ;;
        --sudo) USE_SUDO=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ -n $IP ]] || die '--ip is required'
valid_ip || die "invalid IP address: $IP"

find_fail2ban
find_nft

if (( ${#BAN_JAILS[@]} == 0 && ${#BAN_SETS[@]} == 0 && RULE_MATCH == 0 )); then
    printf 'Nothing found to unban for %s\n' "$IP"
    exit 0
fi

printf 'Bans found for %s:\n' "$IP"
for jail in "${BAN_JAILS[@]+"${BAN_JAILS[@]}"}"; do printf '  fail2ban: jail=%s\n' "$jail"; done
for key in "${BAN_SETS[@]+"${BAN_SETS[@]}"}"; do printf '  nftables: set %s\n' "${key//|/ }"; done
(( RULE_MATCH )) && printf '  nftables: static rule match (NOT auto-removed, delete manually via: nft delete rule ...)\n'

if (( ! ASSUME_YES )); then
    printf 'Remove these bans? [y/N] '
    read -r answer || exit 1
    [[ $answer == [yY] || $answer == [yY][eE][sS] ]] || { printf 'Cancelled\n'; exit 0; }
fi

rc=0
for jail in "${BAN_JAILS[@]+"${BAN_JAILS[@]}"}"; do
    printf 'Fail2ban: unbanning jail=%s ip=%s\n' "$jail" "$IP"
    run_privileged fail2ban-client set "$jail" unbanip "$IP" || {
        printf 'Fail2ban: unban failed jail=%s\n' "$jail" >&2
        rc=1
    }
done
for key in "${BAN_SETS[@]+"${BAN_SETS[@]}"}"; do
    IFS='|' read -r family table set <<< "$key"
    printf 'nftables: deleting family=%s table=%s set=%s ip=%s\n' "$family" "$table" "$set" "$IP"
    run_privileged nft delete element "$family" "$table" "$set" "{" "$IP" "}" || {
        printf 'nftables: delete failed family=%s table=%s set=%s\n' "$family" "$table" "$set" >&2
        rc=1
    }
done

verify_gone || rc=1
exit "$rc"
