#!/usr/bin/env bash
# Check whether an IP is banned in Fail2ban and/or nftables, or whether an IP
# is whitelisted in an nftables set. Read-only.
# To remove bans, use ip-unban.sh.

set -u

PROGRAM=${0##*/}
IP=''
JAIL=''
NFT_FAMILY=''
NFT_TABLE=''
NFT_CHAIN=''
NFT_SET=''
USE_SUDO=0
ALLOWED=0
declare -a IGNORE_JAILS=()
declare -a IGNORE_SETS=()

usage() {
    cat <<EOF
Usage: $PROGRAM --ip ADDRESS [options]

  --ip ADDRESS             IPv4 or IPv6 address to inspect (required)
  --jail NAME              Check only this Fail2ban jail
  --ignore-jail NAME       Ignore Fail2ban jail (repeatable)
  --family FAMILY          Limit nftables search (inet, ip, ip6, ...)
  --table TABLE            Limit nftables search to table
  --chain CHAIN            Limit nftables search to chain
  --set SET                Limit nftables search to set
  --ignore-set SET         Ignore nftables set (repeatable)
  --allowed                Check if IP is in a whitelist nftables set instead
                           of banned state. Requires --set; --family and
                           --table default to inet and filter.
  --sudo                   Run fail2ban-client and nft through sudo
  -h, --help               Show this help

Exit codes: 0 IP banned somewhere, 1 IP not banned, 2 error.
            With --allowed: 0 IP in whitelist set, 1 IP not in set, 2 error.

Examples:
  $PROGRAM --ip 203.0.113.7
  $PROGRAM --ip 2001:db8::7 --family inet --table filter --set blacklist
  $PROGRAM --ip 185.237.102.80 --allowed --set portugal_ipv4
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
    (( found ))
}

check_nft() {
    local rules line family table chain set found=0

    need_command nft
    rules=$(run_privileged nft -a list ruleset 2>/dev/null) || {
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
    (( found ))
}

check_nft_allowed() {
    local family=${NFT_FAMILY:-inet} table=${NFT_TABLE:-filter} set=$NFT_SET out rc

    [[ -n $set ]] || die '--allowed requires --set'
    need_command nft
    out=$(run_privileged nft get element "$family" "$table" "$set" "{ $IP }" 2>&1)
    rc=$?
    if (( rc == 0 )); then
        printf 'nftables: family=%s table=%s set=%s allowed=yes\n' "$family" "$table" "$set"
        return 0
    fi
    printf 'nftables: family=%s table=%s set=%s allowed=no\n' "$family" "$table" "$set"
    [[ -n $out ]] && printf '  nft: %s\n' "$out" >&2
    return 1
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
        --allowed) ALLOWED=1; shift ;;
        --unban) die "--unban moved to ip-unban.sh" ;;
        --sudo) USE_SUDO=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ -n $IP ]] || die '--ip is required'
valid_ip || die "invalid IP address: $IP"

if (( ALLOWED )); then
    check_nft_allowed && exit 0
    exit 1
fi

banned=0
check_fail2ban && banned=1
check_nft && banned=1
(( banned )) && exit 0
exit 1
