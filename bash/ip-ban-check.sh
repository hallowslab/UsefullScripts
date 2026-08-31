#!/usr/bin/env bash
# Check and optionally remove an IP from Fail2ban and nftables.

set -u

PROGRAM=${0##*/}
IP=''
UNBAN='none'
JAIL=''
NFT_FAMILY=''
NFT_TABLE=''
NFT_CHAIN=''
NFT_SET=''
USE_SUDO=0
ASSUME_YES=0
declare -a IGNORE_JAILS=()
declare -a IGNORE_SETS=()

usage() {
    cat <<EOF
Usage: $PROGRAM --ip ADDRESS [options]

Checks:
  --ip ADDRESS             IPv4 or IPv6 address to inspect (required)
  --jail NAME              Check only this Fail2ban jail
  --ignore-jail NAME       Ignore Fail2ban jail (repeatable)
  --family FAMILY          Limit nftables search (inet, ip, ip6, ...)
  --table TABLE            Limit nftables search to table
  --chain CHAIN            Limit nftables search to chain
  --set SET                Limit nftables search to set
  --ignore-set SET         Ignore nftables set (repeatable)

Actions:
  --unban TARGET           Remove from fail2ban, nft, or both
  --yes                    Do not ask for unban confirmation
  --sudo                   Run fail2ban-client and nft through sudo
  -h, --help               Show this help

Examples:
  $PROGRAM --ip 203.0.113.7
  $PROGRAM --ip 203.0.113.7 --unban both
  $PROGRAM --ip 2001:db8::7 --unban nft --family inet --table filter --set blacklist --yes
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

check_fail2ban() {
    local jail_list jail jail_status banned found=0

    need_command fail2ban-client
    jail_list=$(run_privileged fail2ban-client status 2>/dev/null |
        sed -n 's/.*Jail list:[[:space:]]*//p') || {
        printf 'Fail2ban: unable to read jail list\n'
        return 1
    }

    if [[ -n $JAIL ]]; then
        jail_list=$JAIL
    elif [[ -z $jail_list ]]; then
        printf 'Fail2ban: no jails found\n'
        return 1
    fi

    IFS=',' read -ra jail_names <<< "$jail_list"
    for jail in "${jail_names[@]}"; do
        jail=${jail//[[:space:]]/}
        [[ -n $jail ]] || continue
        is_ignored "$jail" "${IGNORE_JAILS[@]}" && continue
        jail_status=$(run_privileged fail2ban-client status "$jail" 2>/dev/null) || {
            printf 'Fail2ban: jail=%s unable to read status\n' "$jail"
            continue
        }
        banned=$(sed -n 's/.*Banned IP list:[[:space:]]*//p' <<< "$jail_status")
        if [[ " $banned " == *" $IP "* ]]; then
            printf 'Fail2ban: jail=%s banned=yes\n' "$jail"
            found=1
        else
            printf 'Fail2ban: jail=%s banned=no\n' "$jail"
        fi
    done
    return "$found"
}

check_nft() {
    local rules line family table chain set found=0
    local -a nft_args=(list ruleset)

    need_command nft
    rules=$(run_privileged nft -a "${nft_args[@]}" 2>/dev/null) || {
        printf 'nftables: unable to read ruleset\n'
        return 1
    }

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

        if contains_ip "$line"; then
            if [[ -n $set ]]; then
                printf 'nftables: family=%s table=%s chain=%s set=%s banned=yes\n' \
                    "$family" "$table" "${chain:--}" "$set"
            else
                printf 'nftables: family=%s table=%s chain=%s set=- rule-match=yes\n' \
                    "$family" "$table" "${chain:--}"
            fi
            found=1
        fi
    done <<< "$rules"
    (( found )) || printf 'nftables: IP not found\n'
    return "$found"
}

unban_fail2ban() {
    local jail_list jail
    need_command fail2ban-client
    if [[ -n $JAIL ]]; then
        jail_list=$JAIL
    else
        jail_list=$(run_privileged fail2ban-client status 2>/dev/null |
            sed -n 's/.*Jail list:[[:space:]]*//p') || return 1
    fi
    IFS=',' read -ra jail_names <<< "$jail_list"
    for jail in "${jail_names[@]}"; do
        jail=${jail//[[:space:]]/}
        [[ -n $jail ]] || continue
        is_ignored "$jail" "${IGNORE_JAILS[@]}" && continue
        printf 'Fail2ban: unbanning jail=%s ip=%s\n' "$jail" "$IP"
        run_privileged fail2ban-client set "$jail" unbanip "$IP" ||
            printf 'Fail2ban: unban failed jail=%s\n' "$jail" >&2
    done
}

unban_nft() {
    local rules line family table chain set key
    local -A seen=()
    rules=$(run_privileged nft -a list ruleset 2>/dev/null) || return 1
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
        [[ -n $set ]] || continue
        contains_ip "$line" || continue
        [[ -n $NFT_FAMILY && $family != "$NFT_FAMILY" ]] && continue
        [[ -n $NFT_TABLE && $table != "$NFT_TABLE" ]] && continue
        [[ -n $NFT_CHAIN && $chain != "$NFT_CHAIN" ]] && continue
        [[ -n $NFT_SET && $set != "$NFT_SET" ]] && continue
        is_ignored "$set" "${IGNORE_SETS[@]}" && continue
        key="$family|$table|$set"
        [[ -n ${seen[$key]:-} ]] && continue
        seen[$key]=1
        printf 'nftables: deleting family=%s table=%s set=%s ip=%s\n' "$family" "$table" "$set" "$IP"
        run_privileged nft delete element "$family" "$table" "$set" "{" "$IP" "}" ||
            printf 'nftables: delete failed family=%s table=%s set=%s\n' "$family" "$table" "$set" >&2
    done <<< "$rules"
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
        --unban) [[ $# -ge 2 ]] || die "--unban needs target"; UNBAN=$2; shift 2 ;;
        --sudo) USE_SUDO=1; shift ;;
        --yes) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ -n $IP ]] || die '--ip is required'
valid_ip || die "invalid IP address: $IP"
case $UNBAN in none|fail2ban|nft|both) ;; *) die '--unban must be fail2ban, nft, or both' ;; esac

fail2ban_result=1
nft_result=1
if [[ $UNBAN == none || $UNBAN == fail2ban || $UNBAN == both ]]; then
    check_fail2ban || fail2ban_result=$?
fi
if [[ $UNBAN == none || $UNBAN == nft || $UNBAN == both ]]; then
    check_nft || nft_result=$?
fi

if [[ $UNBAN != none ]]; then
    if (( ! ASSUME_YES )); then
        printf 'Unban %s from %s? [y/N] ' "$IP" "$UNBAN"
        read -r answer || exit 1
        [[ $answer == [yY] || $answer == [yY][eE][sS] ]] || { printf 'Unban cancelled\n'; exit 0; }
    fi
    [[ $UNBAN == fail2ban || $UNBAN == both ]] && unban_fail2ban
    [[ $UNBAN == nft || $UNBAN == both ]] && unban_nft
fi

if (( fail2ban_result == 0 || nft_result == 0 )); then
    exit 0
fi
exit 1
