#!/usr/bin/env bash
# Report CPU steal time accumulated over system uptime, or measured over a live interval.
# Steal = vCPU time the hypervisor gave to other tenants instead of this VM.

set -u

PROGRAM=${0##*/}
INTERVAL=0

usage() {
    cat <<EOF
Usage: $PROGRAM [options]

Without options the script reports steal time accumulated since boot (over full uptime).

  --interval SECONDS   Sample live steal over N seconds instead of since-boot totals
  -h, --help           Show this help

Examples:
  $PROGRAM
  $PROGRAM --interval 5
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --interval)
            [[ ${2:-} =~ ^[0-9]+$ ]] && [[ $2 -gt 0 ]] || die "--interval needs a positive integer"
            INTERVAL=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

[[ -r /proc/stat && -r /proc/uptime ]] || die "this script needs /proc/stat and /proc/uptime (Linux only)"

HZ=$(getconf CLK_TCK 2>/dev/null || echo 100)

read_cpu() {
    local line
    line=$(< /proc/stat)
    line=${line%%$'\n'*}
    [[ $line == cpu\ * ]] || die "unexpected /proc/stat format"
    read -r _ user nice system idle iowait irq softirq steal _ <<<"$line"
    total=$((user + nice + system + idle + iowait + irq + softirq + steal))
}

fmt_pct() {
    awk -v s="$1" -v t="$2" 'BEGIN { if (t > 0) printf "%.3f", s * 100 / t; else printf "0.000" }'
}

fmt_secs() {
    awk -v j="$1" -v hz="$HZ" 'BEGIN { s = int(j / hz); printf "%d:%02d:%02d", s / 3600, s % 3600 / 60, s % 60 }'
}

read_cpu
start_steal=$steal
start_total=$total
cores=$(grep -c '^processor' /proc/cpuinfo || echo 1)

if [[ $INTERVAL -eq 0 ]]; then
    uptime_secs=$(cut -d. -f1 /proc/uptime)
    wall_secs=$((uptime_secs * cores))

    printf 'Since boot (uptime %s, %s vCPU cores, HZ %s):\n' "$(fmt_secs $((uptime_secs * HZ)))" "$cores" "$HZ"
    printf '  steal:      %s of CPU time (%s s of core time)\n' "$(fmt_pct "$steal" "$wall_secs")%" "$((steal / HZ))"
    printf '  total CPU:  %s s\n' "$((total / HZ))"
    printf '  busy CPU:   %s\n' "$(fmt_pct $((total - idle - iowait)) "$total")%"
    printf '\nNote: steal %% above is share of all vCPU time (uptime x cores).\n'
    exit 0
fi

sleep "$INTERVAL"
read_cpu

d_steal=$((steal - start_steal))
d_total=$((total - start_total))
cap=$((INTERVAL * cores))

printf 'Over last %ss (%s vCPU cores):\n' "$INTERVAL" "$cores"
printf '  steal:      %s of CPU time\n' "$(fmt_pct "$d_steal" "$cap")%"
printf '  steal/raw:  %s of busy CPU time\n' "$(fmt_pct "$d_steal" "$d_total")%"
exit 0
