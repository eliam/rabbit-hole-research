#!/usr/bin/env bash
# Re-run CT enumeration for brands that returned nothing in the first pass
# (crt.sh 502s / rate limits silently produced empty files).
set -u
UA="Mozilla/5.0 (compatible; Intigriti-BugBounty-Research)"
OUT="recon/crt-pass2.raw"
: > "$OUT"

BASES=(
  welt.de hey.bild.de techbook.de myhomebook.de petbook.de stylebook.de
  petbook-magazine.com bild.design bz-berlin.de spring-media.de as-nmt.de
  wissen-sie-mehr.de ein-herz-fuer-kinder.de computerbild.de sportbild.de
  fitbook.de travelbook.de autobild.de
)

for b in "${BASES[@]}"; do
  got=0
  for form in "%25.${b}" "${b}"; do
    for attempt in 1 2 3 4; do
      body=$(curl -sS -m 120 -A "$UA" "https://crt.sh/?q=${form}&output=json" 2>/dev/null)
      if printf '%s' "$body" | jq -e 'length > 0' >/dev/null 2>&1; then
        n=$(printf '%s' "$body" | jq -r '.[].name_value' | wc -l)
        printf '%s' "$body" | jq -r '.[].name_value' >> "$OUT"
        echo "  $b [$form] -> $n names"
        got=1; break 2
      fi
      sleep 6
    done
  done
  [ "$got" = 0 ] && echo "  $b -> STILL EMPTY" >&2
  sleep 3
done

tr '[:upper:]' '[:lower:]' < "$OUT" | sed 's/\*\.//g' | grep -vE '^\s*$' | sort -u > recon/crt-pass2.txt
wc -l < recon/crt-pass2.txt | sed 's/^/unique names pass2: /'
