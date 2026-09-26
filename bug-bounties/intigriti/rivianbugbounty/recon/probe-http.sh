#!/usr/bin/env bash
# probe-http.sh — rate-limited, RoE-compliant HTTP probe for the rivianbugbounty engagement.
#
# RoE requirements honoured here:
#   * Request header: X-Intigriti-Username: <username>  (the only "Required" RoE item)
#   * User agent: RoE says "Not applicable". A truthful, identifiable UA is still sent
#     (CDNs commonly 403 bare curl, which would produce false negatives).
#   * No published rate limit -> self-imposed hard cap of 1 request/second (MIN_DELAY).
#   * GET / HEAD / OPTIONS only. No destructive method, no payload fuzzing, no brute force.
#
# Usage: ./probe-http.sh <url> [curl args...]
#   e.g. ./probe-http.sh https://rivian.com/ -I
set -u

USERNAME="${INTIGRITI_USERNAME:-eliam}"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
MIN_DELAY="${MIN_DELAY:-1}"          # seconds between requests (self-imposed, RoE silent)
STATEFILE="${STATEFILE:-/tmp/rivian-last-request}"
MAXTIME=25

url="$1"; shift || true

# --- enforce the self-imposed rate limit -------------------------------------
if [ -f "$STATEFILE" ]; then
  last=$(cat "$STATEFILE" 2>/dev/null || echo 0)
  now=$(date +%s)
  wait=$(( MIN_DELAY - (now - last) ))
  [ "$wait" -gt 0 ] && sleep "$wait"
fi
date +%s > "$STATEFILE"

exec curl -sS --max-time "$MAXTIME" \
  -H "X-Intigriti-Username: ${USERNAME}" \
  -A "$UA" \
  "$@" "$url"
