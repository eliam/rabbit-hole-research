#!/usr/bin/env bash
# Non-intrusive liveness probe for in-scope Axel Springer hosts.
# GET/HEAD of public roots only. Polite rate limiting (serial, short timeout).
set -u
UA="Mozilla/5.0 (compatible; Intigriti-BugBounty-Research)"
OUT="http-probe.tsv"
: > "$OUT"

probe() {
  local scheme="$1" host="$2"
  local url="${scheme}://${host}/"
  local out code server redirect title
  out=$(curl -sS -k -m 12 --connect-timeout 6 \
        -A "$UA" \
        -D - -o /tmp/body.$$ -w '\n__CODE__%{http_code}\n__REDIR__%{redirect_url}\n' \
        "$url" 2>/dev/null)
  code=$(printf '%s' "$out" | sed -n 's/^__CODE__//p')
  redirect=$(printf '%s' "$out" | sed -n 's/^__REDIR__//p')
  server=$(printf '%s' "$out" | tr -d '\r' | sed -n 's/^[Ss]erver: *//p' | head -1)
  title=$(tr -d '\n' < /tmp/body.$$ 2>/dev/null | sed -n 's/.*<title[^>]*>\(.*\)<\/title>.*/\1/ip' | head -c 120)
  rm -f /tmp/body.$$
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$host" "$scheme" "${code:-ERR}" "${server:-}" "${title:-}" "${redirect:-}" >> "$OUT"
  printf '%-32s %-5s %-4s %-18s %s\n' "$host" "$scheme" "${code:-ERR}" "${server:-}" "${title:-}"
}

while read -r h; do
  [ -z "$h" ] && continue
  probe https "$h"
  sleep 0.4
done < targets.txt

echo "--- HTTP fallback for hosts with no HTTPS 200/30x ---"
while IFS=$'\t' read -r host scheme code rest; do
  [ "$scheme" = "https" ] || continue
  case "$code" in
    000|ERR|*" "*) probe http "$host"; sleep 0.4 ;;
  esac
done < "$OUT"
