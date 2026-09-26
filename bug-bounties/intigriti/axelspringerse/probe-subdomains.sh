#!/usr/bin/env bash
# Probe resolved in-scope subdomains over HTTPS/HTTP (root GET, non-intrusive).
set -u
UA="Mozilla/5.0 (compatible; Intigriti-BugBounty-Research)"
IN="${1:-resolved.tsv}"
OUT="${2:-subdomains-http.tsv}"
: > "$OUT"

probe_one() {
  local host="$1"
  local ua="Mozilla/5.0 (compatible; Intigriti-BugBounty-Research)"
  local r code server title final
  r=$(curl -sS -k -m 10 --connect-timeout 5 -A "$ua" -L -o /tmp/pb.$$$$ -w '%{http_code}\t%{url_effective}' "https://$host/" 2>/dev/null)
  code=$(printf '%s' "$r" | cut -f1)
  final=$(printf '%s' "$r" | cut -f2)
  if [ "$code" = "000" ] || [ -z "$code" ]; then
    r=$(curl -sS -k -m 10 --connect-timeout 5 -A "$ua" -L -o /tmp/pb.$$$$ -w '%{http_code}\t%{url_effective}' "http://$host/" 2>/dev/null)
    code=$(printf '%s' "$r" | cut -f1); final=$(printf '%s' "$r" | cut -f2)
    [ "$code" = "000" ] && { rm -f /tmp/pb.$$$$; return; }
  fi
  title=$(tr -d '\n' < /tmp/pb.$$$$ 2>/dev/null | sed -n 's/.*<title[^>]*>\(.*\)<\/title>.*/\1/ip' | cut -c1-80)
  rm -f /tmp/pb.$$$$
  printf '%s\t%s\t%s\t%s\n' "$host" "$code" "$final" "${title:-}"
}
export -f probe_one

cut -f1 "$IN" | sort -u | xargs -P 25 -I{} bash -c 'probe_one "{}"' >> "$OUT" 2>/dev/null
echo "live endpoints: $(wc -l < "$OUT")"
