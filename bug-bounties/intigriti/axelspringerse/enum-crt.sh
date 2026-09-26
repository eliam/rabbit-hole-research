#!/usr/bin/env bash
# Passive subdomain enumeration via crt.sh certificate transparency logs.
# Used to turn the RoE wildcard entries into concrete, in-scope hostnames.
set -u
UA="Mozilla/5.0 (compatible; Intigriti-BugBounty-Research)"
OUT="crt-subdomains.txt"
: > "$OUT"

# Wildcard bases from the RoE (apex form used for CT lookup)
BASES=(
  asadcdn.com
  auth.bild.de
  hey.bild.de
  sportbild.de
  bild.tv
  computerbild.de
  welt.de
  bild.de
  bild.design
  autobild.de
  bz-berlin.de
  spring-media.de
  springtools.de
  as-nmt.de
  fitbook.de
  myhomebook.de
  petbook.de
  petbook-magazine.com
  stylebook.de
  techbook.de
  travelbook.de
  wissen-sie-mehr.de
  ein-herz-fuer-kinder.de
  germany.politico.eu
  politico.eu
  emarketer.com
  newsos.com
)

for b in "${BASES[@]}"; do
  cnt=0
  for attempt in 1 2 3; do
    body=$(curl -sS -m 60 -A "$UA" "https://crt.sh/?q=%25.${b}&output=json" 2>/dev/null)
    if [ -n "$body" ] && [ "$body" != "[]" ]; then
      echo "$body" | jq -r '.[].name_value' 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr '\n' '\n'
      cnt=1; break
    fi
    sleep 5
  done
  [ "$cnt" = 0 ] && echo "# no crt.sh data: $b" >&2
  sleep 2
done | sed 's/\*\.//g' | grep -vE '^\s*$' | sort -u > "$OUT.raw"

# Keep only hostnames that are actually in-scope (belong to a wildcard/apex we own)
{
  for b in "${BASES[@]}"; do
    grep -E "(^|\.)${b//./\\.}$" "$OUT.raw"
  done
} | sort -u > "$OUT"
rm -f "$OUT.raw"
wc -l < "$OUT" | sed 's/^/subdomains found: /'
