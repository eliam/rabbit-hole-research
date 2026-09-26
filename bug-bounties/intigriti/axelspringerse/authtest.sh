#!/usr/bin/env bash
# Authenticated access-control test harness — Axel Springer (Intigriti axelspringerse)
#
# PREREQUISITES
#   creds/account-a.cookie   raw Cookie header value for account A
#   creds/account-b.cookie   raw Cookie header value for account B
#   e.g.  ory_kratos_session=MTc...; csrftoken=abc...
#
# Both accounts MUST be your own test accounts. Tests are read-only except the
# one guarded cross-session DELETE (enable with CONFIRM_DELETE=1).
#
# Usage:  ./authtest.sh
#         CONFIRM_DELETE=1 ./authtest.sh     # also run the destructive probe
set -u

UA="Mozilla/5.0 (compatible; Intigriti-BugBounty-Research)"
API="https://consumer-api.prod.auth.bild.de"
CA="creds/account-a.cookie"
CB="creds/account-b.cookie"
OUT="authtest-results.tsv"
: > "$OUT"

CONFIRM_DELETE="${CONFIRM_DELETE:-0}"

die() { echo "ERROR: $*" >&2; exit 1; }
[ -s "$CA" ] || die "missing $CA  (paste account A cookie there)"
[ -s "$CB" ] || die "missing $CB  (paste account B cookie there)"

ck() { tr -d '\r\n' < "$1"; }

# req <label> <cookie-file> <METHOD> <url> [json-body]
req() {
  local label="$1" jar="$2" method="$3" url="$4" body="${5:-}"
  local args=(-sS -k -m 15 -A "$UA" -X "$method" -H "Cookie: $(ck "$jar")"
              -H 'Accept: application/json' -w '\n__META__%{http_code}|%{size_download}')
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data-raw "$body")
  local raw; raw=$(curl "${args[@]}" "$url" 2>/dev/null)
  local meta="${raw##*__META__}"; local resp="${raw%__META__*}"
  local code="${meta%%|*}"
  printf '%s\t%s\t%s\t%s\n' "$label" "$code" "$method" "$url" >> "$OUT"
  printf '  [%s] %-46s %s\n' "$code" "$label" "$(printf '%s' "$resp" | tr -d '\n' | cut -c1-150)"
  LAST_RESP="$resp"
}

echo "=== 0. session identity ==="
for pair in "A:$CA" "B:$CB"; do
  who="${pair%%:*}"; jar="${pair#*:}"
  req "whoami-$who" "$jar" GET "$API/sessions/whoami"
  AID=$(printf '%s' "$LAST_RESP" | jq -r '.identity.id // empty' 2>/dev/null)
  eval "ID_${who}=\"$AID\""
  printf '        -> identity.id = %s\n' "${AID:-<none>}"
done
[ "${ID_A:-}" = "${ID_B:-}" ] && echo "  !! A and B resolved to the SAME identity — use two distinct accounts" || echo "  ok: distinct identities"

echo
echo "=== 1. own-session listing (must not leak the other account) ==="
for pair in "A:$CA" "B:$CB"; do
  who="${pair%%:*}"; jar="${pair#*:}"
  req "sessions-list-$who" "$jar" GET "$API/sessions"
  printf '        ids: %s\n' "$(printf '%s' "$LAST_RESP" | jq -r '[.[]?.id]|join(",")' 2>/dev/null)"
  printf '        identities leaked: %s\n' "$(printf '%s' "$LAST_RESP" | jq -r '[.[]?.identity.id]|unique|join(",")' 2>/dev/null)"
  eval "SESS_IDS_${who}=\"$(printf '%s' "$LAST_RESP" | jq -r '[.[]?.id]|join(" ")' 2>/dev/null)\""
done
echo "  A session ids: ${SESS_IDS_A:-<none>}"
echo "  B session ids: ${SESS_IDS_B:-<none>}"
if [ -n "${SESS_IDS_B:-}" ] && [ -n "${SESS_IDS_A:-}" ]; then
  for sid in $SESS_IDS_B; do
    case " ${SESS_IDS_A} " in *" $sid "*) echo "  !! B's session id ($sid) also appears in A's list — cross-account leak" ;; esac
  done
fi

echo
echo "=== 2. settings / identity isolation (read-only) ==="
for pair in "A:$CA" "B:$CB"; do
  who="${pair%%:*}"; jar="${pair#*:}"
  req "settings-browser-$who" "$jar" GET "$API/self-service/settings/browser"
  loc=$(printf '%s' "$LAST_RESP" | jq -r '.error // empty' 2>/dev/null)
done
# settings flow needs a browser flow id; fetch via redirect then the API
FLOWS=$(curl -sS -k -m 15 -A "$UA" -H "Cookie: $(ck "$CA")" -D - -o /dev/null "$API/self-service/settings/browser" 2>/dev/null | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')
SFID=$(printf '%s' "$FLOWS" | sed -n 's/.*flow=\([^&]*\).*/\1/p')
if [ -n "$SFID" ]; then
  req "settings-flow-A" "$CA" GET "$API/self-service/settings/flows?id=$SFID"
  printf '        identity in flow: %s\n' "$(printf '%s' "$LAST_RESP" | jq -r '.identity.id // "<none>"' 2>/dev/null)"
  printf '        traits: %s\n' "$(printf '%s' "$LAST_RESP" | jq -c '.identity.traits // {}' 2>/dev/null | head -c 200)"
fi

echo
echo "=== 3. cross-session DELETE (destructive — only with CONFIRM_DELETE=1) ==="
echo "  Purpose: can A revoke B's session? Tests /sessions/{id} object ownership."
if [ "$CONFIRM_DELETE" = "1" ]; then
  for sid in ${SESS_IDS_B:-}; do
    echo "  A -> DELETE B's session $sid"
    req "CROSS-DELETE-A-revokes-B/$sid" "$CA" DELETE "$API/sessions/$sid"
  done
  echo "  re-checking B is still logged in:"
  req "whoami-B-after" "$CB" GET "$API/sessions/whoami"
else
  echo "  SKIPPED (set CONFIRM_DELETE=1 to run). Reversible: B can simply log in again."
fi

echo
echo "=== 4. token-exchange surface (authenticated) ==="
req "token-exchange-A" "$CA" GET "$API/sessions/token-exchange?init_code=x&return_to_code=y"

echo
echo "results written to $OUT"
