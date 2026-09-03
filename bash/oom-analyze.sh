#!/usr/bin/env bash
# Analyze OOM killer events: boot history, killed processes, memory at kill time.
# Reads persistent journal by default, or plain/compressed syslog files.

set -u

PROGRAM=${0##*/}
SINCE=''
UNTIL=''
BOOT='all'
DETAIL=0
SHORT_BOOT_MIN=60
declare -a FILES=()
SCAN_SYSLOG=0

usage() {
    cat <<EOF
Usage: $PROGRAM [options]

Analyzes OOM killer events. Default source: kernel journal across all boots.

Sources:
  --file FILE            Parse this log file instead of journal (repeatable)
  --syslog               Scan /var/log/{messages,syslog,kern.log} incl. rotated

Journal filters:
  --boot ID              Journal boot id (default: all)
  --since TIME           journalctl --since (e.g. "2 days ago", "2026-09-01")
  --until TIME           journalctl --until

Output:
  --detail               Print raw OOM blocks including process dump tables
  --short-boot MIN       Flag boots shorter than MIN minutes (default 60)
  -h, --help             Show this help

Examples:
  $PROGRAM
  $PROGRAM --since "7 days ago" --detail
  $PROGRAM --syslog --file /var/log/custom.log
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --file) [[ -n ${2:-} ]] || die "--file needs a path"; FILES+=("$2"); shift 2 ;;
        --syslog) SCAN_SYSLOG=1; shift ;;
        --boot) BOOT=$2; shift 2 ;;
        --since) SINCE=$2; shift 2 ;;
        --until) UNTIL=$2; shift 2 ;;
        --detail) DETAIL=1; shift ;;
        --short-boot) [[ ${2:-} =~ ^[0-9]+$ ]] || die "--short-boot needs minutes"; SHORT_BOOT_MIN=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

get_log() {
    if [[ ${#FILES[@]} -gt 0 ]]; then
        cat -- "${FILES[@]}"
    elif [[ $SCAN_SYSLOG -eq 1 ]]; then
        zgrep -h '' /var/log/messages* /var/log/syslog* /var/log/kern.log* 2>/dev/null
    else
        command -v journalctl >/dev/null 2>&1 || die "journalctl missing; use --file or --syslog"
        local -a jc=(journalctl -k -a -o short-iso)
        [[ -n $BOOT ]] && jc+=(-b "$BOOT")
        [[ -n $SINCE ]] && jc+=(--since "$SINCE")
        [[ -n $UNTIL ]] && jc+=(--until "$UNTIL")
        "${jc[@]}" --no-pager 2>/dev/null
    fi
}

OOM_RE='invoked oom-killer|Out of memory|Kill(ed)? process|oom-kill:|Memory cgroup out of memory|Zap pid|oom_score'

log=$(get_log) || die "no log source readable"

printf '=== BOOT HISTORY ===\n'
if [[ ${#FILES[@]} -eq 0 && $SCAN_SYSLOG -eq 0 ]] && command -v journalctl >/dev/null 2>&1; then
    journalctl --list-boots --no-pager 2>/dev/null | awk -v min="$SHORT_BOOT_MIN" '
        function epoch(d, t,   cmd, e) {
            cmd = "date -u -d \"" d " " t "\" +%s"
            if ((cmd | getline e) > 0) { close(cmd); return e + 0 }
            close(cmd)
            return -1
        }
        NF >= 10 && $1 ~ /^-?[0-9]+$/ {
            start = $4 " " $5
            end_ = $8 " " $9
            d = (epoch($8, $9) - epoch($4, $5)) / 60
            flag = ""
            if ($1 != "" && $1 != 0 && d >= 0 && d < min) flag = sprintf("  <<< SHORT BOOT (<%d min)", min)
            if (d >= 0) printf "%4s  %-36s  %s -> %s  (%.0f min)%s\n", $1, $2, start, end_, d, flag
            else        printf "%4s  %-36s  %s -> %s\n", $1, $2, start, end_
            next
        }
        $1 ~ /^-?[0-9]+$/ { print }'
    printf '\n'
else
    printf '(skipped: not using journal)\n\n'
fi

printf '=== OOM KILL EVENTS ===\n'
kill_lines=$(printf '%s\n' "$log" | grep -E 'Kill(ed)? process' || true)
if [[ -z $kill_lines ]]; then
    printf 'none found in source\n\n'
else
    printf '%s\n' "$kill_lines" | awk '
        {
            line = $0
            time = ""
            if (match(line, /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]+/)) time = substr(line, 1, RLENGTH - 2)
            else if (match(line, /^[A-Za-z]{3} [ 0-9]{2} [0-9:]{8}/)) time = substr(line, RSTART, RLENGTH)
            match(line, /[Kk]ill(ed)? process ([0-9]+) \(([^)]*)\)/, m)
            pid = m[2]; victim = m[3]
            vm = "-"; rss = "-"; adj = "-"
            if (match(line, /total-vm:([0-9]+)kB/, a)) vm = sprintf("%.0f", a[1] / 1024)
            if (match(line, /anon-rss:([0-9]+)kB/, a)) rss = sprintf("%.0f", a[1] / 1024)
            if (match(line, /oom_score_adj:(-?[0-9]+)/, a)) adj = a[1]
            printf "%-22s pid=%-8s %-24s anon-rss=%-8s MB total-vm=%-8s MB adj=%s\n", time, pid, substr(victim, 1, 24), rss, vm, adj
        }'
    printf '\n=== VICTIM FREQUENCY ===\n'
    printf '%s\n' "$kill_lines" | awk '
        { if (match($0, /[Kk]ill(ed)? process ([0-9]+) \(([^)]*)\)/, m)) count[m[3]]++ }
        END { for (v in count) printf "%6d  %s\n", count[v], v }' | sort -rn
    printf '\n'
fi

printf '=== OOM TRIGGERS (who asked for memory) ===\n'
printf '%s\n' "$log" | grep -E 'invoked oom-killer' | awk '
    { for (i = 1; i <= NF; i++) if ($i == "invoked") { print $(i - 1); next } }' | sort | uniq -c | sort -rn
printf '%s\n' "$log" | grep -E 'Memory cgroup out of memory' | head -5
printf '\n'

if [[ $DETAIL -eq 1 ]]; then
    printf '=== RAW OOM BLOCKS (process table at kill time) ===\n'
    printf '%s\n' "$log" | sed -n '/invoked oom-killer/,/[Kk]ill\(ed\)\? process/p'
    printf '%s\n' "$log" | sed -n '/Memory cgroup out of memory/,/[Kk]ill\(ed\)\? process/p'
fi
