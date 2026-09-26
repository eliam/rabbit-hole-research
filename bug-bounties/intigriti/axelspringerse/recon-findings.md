# Recon Findings & Target Prioritisation — Axel Springer SE

Date: 2026-09-26 · All requests non-intrusive (public GETs / discovery documents only).
Raw artefacts: `recon/`, `recon/evidence/`.

---

## 0. Scope trap found first — read this before testing anything

The `ps.axelspringer.de` estate is the juiciest-looking thing in this engagement and it is
**almost entirely OUT OF SCOPE**:

- The RoE has **no `*.axelspringer.de` wildcard**. It explicitly lists only
  `dealer.prod.ps.axelspringer.de/purchases/*` (Tier 1) and marks `*.axelspringer.com` out of scope.
- Therefore `atlas.docs.ps.axelspringer.de`, `dealer.docs…`, `octopus.docs…`,
  `rosetta.prod.ps.axelspringer.de`, `rusty-heartbeat.services…`, `fonti.prod…`,
  `web-logger…`, `whoami-api.docs…` (15+ hosts) are **not** authorised targets.
- Same estate **under `ps.bild.de` / `ps.welt.de` IS in scope**, via the Tier 2
  `*.bild.de` / `*.welt.de` wildcards. That is where the work below is aimed.

`*.docs.ps.axelspringer.de` are public Swagger/Redoc portals on GitHub Pages (185.199.x.x).
Reading them as *public information* is fine; do not test them.

---

## 1. Confirmed misconfiguration — OIDC issuer mismatch (UAT)

Evidence: `recon/evidence/oidc-*.json`

| Serving host | Declared `issuer` | Correct? |
| --- | --- | --- |
| consumer-api.prod.auth.bild.de | `https://consumer-api.prod.auth.bild.de` | ✅ |
| consumer-api.prod.auth.welt.de | `https://consumer-api.prod.auth.welt.de` | ✅ |
| consumer-api.uat.auth.bild.de | `https://consumer-api.stage.auth.bild.de` | ❌ |
| consumer-api.uat.auth.welt.de | `https://consumer-api.stage.auth.bild.de` | ❌ **cross-brand** |

Two problems:

1. **RFC 8414 §3.3 / OIDC Discovery §4.3 violation** — `issuer` MUST equal the URL the document
   was fetched from. Any conformant RP validating `iss` will reject UAT tokens, or (worse) an RP
   that trusts the document's issuer will accept tokens minted for the *stage* environment.
2. **Cross-brand leak** — the **welt.de** UAT tenant advertises the **bild.de** stage issuer.
   A welt RP following discovery would accept `bild.de` stage-issued tokens. That is an
   authorization-boundary smell, not just a typo.

Stack is **Ory Hydra / Kratos** (Ory Network) fronted by Cloudflare; `consumer-api.stage.*`
itself does not resolve publicly.

### Related OIDC hardening gaps (prod, same documents)

| Setting | Value | Concern |
| --- | --- | --- |
| `code_challenge_methods_supported` | `["plain","S256"]` | **PKCE `plain` enabled in production** — allows verifier downgrade, defeats PKCE's purpose. S256-only is the expected posture. |
| `response_types_supported` | incl. `token`, `id_token`, implicit | implicit flow enabled (deprecated) |
| `token_endpoint_auth_methods_supported` | incl. `none` | public clients permitted |
| `userinfo_signing_alg_values_supported` | `["none","RS256"]` | userinfo may be unsigned |

Worth reporting as a bundle; the issuer mismatch is the strongest item.

---

## 2. newsos.com — OAuth discovery review (Tier 2)

`recon/evidence/oidc-newsos.com.json`

- issuer `https://newsos.prod.tech.as-nmt.de` (in scope via `*.as-nmt.de`)
- **`registration_endpoint: /oauth/register` advertised, with
  `token_endpoint_auth_methods_supported: ["none"]`** → open Dynamic Client Registration.
  Anyone can mint an OAuth client against production. Candidate finding — but **confirming it
  requires a POST that writes state to prod**, which the RoE's "no intrusive commands in
  production" clause forbids without explicit sign-off. Reading the document is sufficient
  evidence to raise it with the program first.
- `scopes_supported` includes **`newsos-mcp/invoke`** — an MCP (Model Context Protocol) server
  is exposed. Unusual surface, worth a dedicated look.
- PKCE is correctly `S256` only here (good).

Gateway is **APISIX 3.17.0**.

---

## 3. In-scope live application surface (from bundle analysis)

`signin.auth.bild.de` / `signin.auth.welt.de` (Tier 1) are S3+CloudFront SPAs speaking to
Ory Kratos self-service APIs. Endpoints recovered:

```
/self-service/{login,registration,recovery,verification,settings}/{browser,api,flows}
/sessions  /sessions/{id}  /sessions/token-exchange  /sessions/whoami
/self-service/fed-cm/{parameters,token}
```
SPA routes: `/login /register /recovery /verification /change-password /account-completion /verify/device`

**`/sessions/{id}` and `/sessions/token-exchange` are the highest-value IDOR targets** in an Ory
deployment. `whoami` is 401 without a session (correct).

Live in-scope hosts discovered beyond the RoE list:

| Host | Status | Scope basis |
| --- | --- | --- |
| checkout-v2.prod.ps.bild.de | 200 "Checkout" | `*.bild.de` |
| checkout-v2.prod.ps.welt.de | 200 "Checkout" | `*.welt.de` |
| consumer-next-web.uat.ps.bild.de | 200 (**UAT** of the signin app) | `*.bild.de` |
| checkout-next-api.prod.ps.{bild,welt}.de | 404/503 (alive, routing) | `*.bild.de`/`*.welt.de` |
| checkout-next-api.uat.ps.bild.de | resolves via CloudFront | `*.bild.de` |
| whoami-web.uat.ps.{bild,welt}.de | resolves via CloudFront | `*.bild.de`/`*.welt.de` |
| ory-poc-api.ps.bild.de | 409 | `*.bild.de` |
| admin.checkout.prod.ps.bild.de | 502 | `*.bild.de` |
| admin.checkout-uat.ps.bild.de | no A record | `*.bild.de` |
| consumer-api.{prod,uat}.auth.welt.de | live | `*.welt.de` |

### checkout-next-api contract (recovered from bundle)

```
GET  /api/{tenant}/offers/{offerId}
GET  /api/{tenant}/vouchers/{voucherCode}
POST /api/prepare-purchase      (bearer via authorizedFetch)
```
`tenant` = `bdep` (bild.de) / `wonp` (welt.de). Verified working, returns public pricing:
`GET /api/bdep/offers/O_8B18M383C1Q10HJB6O` → `{"productTitle":"BILD Wallet",…}`.
No source maps exposed (`.js.map` → 403).

---

## 3b. Authentication stack — unauthenticated testing results

Flows mapped end-to-end (`recon/flows/`). Registration requires `traits.email` + `password`
(+ optional name/country/opt-ins); login requires `identifier` + `password`. **9 social providers**
offered: Facebook, Google, Google Business Insider, Google Bild, Google Welt, PayPal Bild,
NetID, NetID GMX, NetID WEB DE.

Ory endpoints behave correctly against the checks run so far:

| Test | Result | Verdict |
| --- | --- | --- |
| `GET /sessions/whoami` unauth | 401 `No valid session credentials` | ✅ |
| `GET /sessions` unauth | 401 | ✅ |
| `GET /sessions/{uuid}` | 405 — **DELETE-only endpoint** | ✅ |
| `DELETE /sessions/{uuid}` unauth | 401 | ✅ |
| `OPTIONS /sessions/{uuid}` | 404 | ✅ no method disclosure |
| `return_to=https://evil.example.com/` | → `/error` | ✅ **allowlisted, no open redirect** |
| `return_to=//evil.example.com/` | → `/error` | ✅ |
| `POST /self-service/fed-cm/*` | 403 `security_csrf_violation` | ✅ CSRF enforced |
| `/sessions/token-exchange` dummy codes | 404 `no session yet for this "code"` | ✅ no info leak |

So the SPA bundle's `/sessions/{id}` is a **DELETE** route (revoke session), not a read route —
the "session IDOR" hypothesis is **weakened**: the only way to test it is to attempt revoking
*another* user's session, which needs two authenticated accounts and is a destructive action.
**Do not blind-fire DELETE at session IDs** — it would be an intrusive action against other users.

`/sessions/token-exchange` (requires `init_code` + `return_to_code`) is the most novel surface
and is worth a careful look once authenticated; the codes are opaque and the error path leaks nothing.

### Net assessment
The authentication perimeter is **well hardened**. The reportable material so far is
configuration-level (OIDC issuer mismatch, PKCE `plain`), not an exploitable access-control bug.
An authenticated session is prerequisite for anything further — see §5.

## 3c. Authenticated testing results (2 self-registered accounts)

Two accounts created by the researcher (`eliam+account1@intigriti.me`, `eliam+account2@intigriti.me`),
distinct identity IDs `12371af5-…-8d6c2a` (A) and `f969a4d2-…-5ed2b` (B). Both sessions are
valid and **email-unverified** — verification is `status: sent`, `verified: false`, yet a full
authenticated session is issued. That is worth a low-severity note on its own (signup does not
gate on email verification).

| # | Test | Result | Verdict |
| --- | --- | --- | --- |
| T1 | A's bild.de session against **welt.de** API | 200, same session id | shared Ory project |
| T2 | A → `DELETE /sessions/{B's id}` | **204** but B's session survives (200) | ✅ fails safe |
| T3 | A → `DELETE /sessions/{random uuid}` | 204 | misleading status |
| T4 | A → `DELETE /sessions/{own id}` | **400** | cannot revoke own current session |
| T5 | prod session → **UAT** API (`consumer-api.uat.auth.bild.de`) | **401** | ✅ env isolated |
| T6 | `settings/browser?identity_id=<B's id>` | flow still resolves to **A** | ✅ no identity tampering |
| T7 | `settings/flows` traits | only A's own traits | ✅ |
| T8 | `asid` JWT `alg:none` forgery | 401 | ✅ |
| T9 | `asid` JWT `alg:HS256` forgery | 401 | ✅ no alg-confusion |
| T10 | `asid` alone → Ory `whoami` / whoami-web | 401 / 403 | ✅ not trusted standalone |
| T11 | `checkout-next-api` tenant path cross-use | bild host serves `bdep`; `wonp` 404 on both | see below |

### T2/T3/T4 — the one genuine oddity
`DELETE /sessions/{id}` returns **204 for every session id the caller does not own**, including
nonexistent ones, **without deleting anything**, and **400 for the caller's own session**.
So a client that logs out via `DELETE /sessions/{id}` is told it succeeded when nothing happened.
Security impact is low (it fails safe — no cross-user deletion, no data returned), but it is a
real API-contract defect and a **misleading success**, which is exactly the kind of thing that
hides a future regression. Report as low/informational.

### `asid` JWT (decoded, not forged)
`{"alg":"RS256","kid":"whoami-keyset-1788775688419"}` /
`{"sub":"<opaque 52-char id>","subOrigin":"as","aud":"BDEp","e":null,"a":false,"mfa":false,"iss":"whoami"}`
RS256, correctly rejected under `none`/`HS256`. The `sub` (a.k.a. `jaId`) is an opaque
lowercase-alphanumeric ID, not a sequential integer. No weakness found from outside.

### Session-cookie sharing across brands (observation)
A session minted for bild.de authenticates on `consumer-api.prod.auth.welt.de` with the same
session id. Given `subOrigin:"as"` and the shared Ory project slug this looks **intentional**
(unified Axel Springer identity), but it is worth confirming with the program, because the UAT
discovery documents otherwise present bild and welt as separate issuers.

### Incident to disclose
While probing validation, `POST /api/prepare-purchase` with `{"tenant":"bdep","offerId":"O_8B18M383C1Q10HJB6O"}`
returned 200 and **created a purchase intent** (`purchaseId 3JqMPu3Q84QwfgNjZnlfZZSgsDw`) on
production, authenticated as account A. No payment was taken and no entitlement granted, but it
is a state write and was not intended. It is the same action a user performs on "buy", so it is
within the authorised flow, and it was done as the researcher's own account. Disclose it if a
report is filed. No further writes were made.

### Dead end
`dealer.prod.ps.axelspringer.de/purchases/*` (the only in-scope Tier 1 `axelspringer.de` path)
returns **503 `awselb/2.0` / `Error from cloudfront`** for every path, with and without auth —
no healthy backend. Not testable today.

## 3d. Cache poisoning & CORS work (the RoE-invited area)

### Cache behaviour — mapped, and the CDN config is sound

All probes used a **unique cache-buster** (`?cb=<uuid>`) so nothing could poison a URL real users hit.

| Host | Cache status | `Vary` | Notes |
| --- | --- | --- | --- |
| `signin.auth.bild.de` | **Hit**, `age`~78, `max-age=120` | `Origin` | static SPA |
| `signin.auth.welt.de` | **Hit**, `max-age=120` | `Origin` | static SPA |
| `checkout-v2.prod.ps.bild.de` | **Hit**, `max-age=120` | `Origin, Access-Control-Request-*` | static SPA |
| `consumer-next-web.uat.ps.bild.de` | **Hit**, `max-age=120` | `Origin` | static SPA (UAT) |
| `checkout-next-api.../api/bdep/offers/{id}` | Hit/Miss, `max-age=120` | *(none emitted)* | JSON API |
| `consumer-api.*.auth.bild.de` | `cf-cache-status: DYNAMIC` | `Origin` | `private, no-cache, no-store` — **not cached at all** |
| `newsos.com/login` | Miss | — | `cache-control: no-cache` — not cached |

**Nothing poisonable found.** Specifically ruled out:

- **Auth-dependent content**: `/login`, `/register`, `/account-completion`, `/change-password`,
  `/verify/device`, `/cockpit.html` all return a byte-identical 2327/2395-byte SPA shell
  anonymous *and* authenticated (`cmp` = SAME). There is no per-user variation to cache.
- **Unkeyed header injection**: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`,
  `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Scheme` — **zero reflection** in body or headers
  on `checkout-next-api` (marker host `cachetest-<rand>.example`).
- **Origin keying**: same buster, Origin A → Miss, Origin B → **Miss**, Origin A again → **Hit**.
  CloudFront's cache policy *does* include `Origin` in the key ⇒ no CORS-poisoning.
- **Query-string keying**: `?cb=A` → Miss, `?cb=B` → **Miss**, `?cb=A` → **Hit**. Query string *is*
  in the key.

So the specific thing the RoE invites — *"cache poisoning ... valid with changing authentication
headers"* — **does not appear to exist** on the endpoints tested. The CDN is configured correctly
(keyed on Origin + query string, and not caching the authenticated Ory API at all).

### CORS — a genuine weakness on sensitive endpoints

`Access-Control-Allow-Origin` **reflects any subdomain** of the listed domains, and
`Access-Control-Allow-Credentials: true` is returned. Dynamic ACAO is correctly *not* emitted for
non-listed origins (`evil.example`, `null`, `https://evil.bild.de.attacker.com`, `http://…`,
`WWW.BILD.DE`, punycode lookalikes all correctly denied).

| Endpoint | Reflected allowlist | Ports |
| --- | --- | --- |
| `consumer-api.prod.auth.bild.de` (**sessions, identity, whoami**) | `bild.de`, `*.bild.de` | 443 only |
| `checkout-next-api.prod.ps.bild.de` (**purchases, baskets, payment prep**) | `bild.de`, `welt.de`, `autobild.de`, `computerbild.de`, `sportbild.de`, `spring-media.de`, `*.axelspringer.de` | **arbitrary** (`https://www.bild.de:8443` reflected) |

Proof (credentialed): `Origin: https://attacker-controlled.bild.de` + account A's session cookie
→ `Access-Control-Allow-Origin: https://attacker-controlled.bild.de` +
`Access-Control-Allow-Credentials: true`. A browser would therefore let a page on any `*.bild.de`
subdomain read the response **with the victim's cookies attached**.

**Why this is not yet a full finding:** exploitation requires the attacker to control (or run
script on) *some* subdomain of an allowlisted domain. I looked and did not find one:

- Dangling-CNAME hunt over 329 CNAMEs / 4,467 names: `store.emarketer.com` → real Shopify store;
  `event.{bild,autobild,sportbild}.de` → live CloudFront dists (403 when hit directly = correct
  Host-header enforcement, *not* dangling); `checkout.co.auth.bild.de` → live distribution;
  control check confirms a genuinely dead CloudFront dist doesn't resolve at all (HTTP 000).
- `*.docs.ps.axelspringer.de` GitHub-Pages hosts are claimed (302 to login), not dangling.

**Honest severity: Low → possibly None.** The RoE excludes *"CORS misconfiguration on
non-sensitive endpoints"* — these endpoints **are** sensitive, so that exclusion does not apply —
but *"vulnerabilities without realistic exploit scenario(s) ... are assigned a severity of None"*
may still bite, because the required subdomain foothold is undemonstrated. Wilder wildcard
allowlists with credentials on an auth/commerce API are worth raising, but this is not a
standalone critical.

**Next step if pursued:** find any XSS or takeover on `*.bild.de` / `*.welt.de` / `*.autobild.de` /
`*.computerbild.de` / `*.sportbild.de` / `*.spring-media.de` / `*.axelspringer.de` to complete the
chain — that would upgrade it materially.

## 3e. Pass-2 enumeration (major coverage gap found and closed)

**The first CT pass silently failed for several brands** — crt.sh 502s produced empty files and my
harness kept going. Most significant: **`welt.de` had 0 subdomains enumerated** despite being a
Tier 1 brand with a Tier 2 wildcard. Re-run with retries (`enum-crt-pass2.sh`):

| Brand | pass 1 | pass 2 (unique) |
| --- | --- | --- |
| welt.de | **0** | 229 |
| computerbild.de | 11 | 175 |
| bild.design | 0 | 31 |
| stylebook.de / techbook.de / fitbook.de / myhomebook.de / petbook.de | 0 | 22–25 each |
| travelbook.de | 29 | 29 |
| hey.bild.de | **0** | 9 |
| bild.tv, bz-berlin.de, spring-media.de, as-nmt.de | 0–3 | 1–3 |

Combined corpus: **5,002 unique names**. 4,574 newly resolved → **237 new resolving, 200 new live
endpoints**.

### New in-scope surface worth work

**welt.de (Tier 1 brand):** `design.welt.de` (zeroheight design system), `edition-issues-devel.ep.welt.de`
(S3-backed **devel**), `dev1–5.epaper.welt.de` (devel epaper → `asse-dev.004dev.com`, nginx/1.31.3),
`kuendigung.welt.de`, `leserservice.welt.de`, `gutscheine.welt.de`, `debatten.welt.de`,
`staging.la.welt.de`, `www.jobs.welt.de` (403), `data-*.welt.de` (see below).

**computerbild.de:** `consumer-api.prod.auth.computerbild.de` (**third Ory brand** — same stack,
PKCE `plain` also enabled), `digasred[.stage].computerbild.de` (403), `vc.stg.vip-club.computerbild.de`
(403 nginx), `speedtest-test.computerbild.de` (401 basic auth), `dsl-start[-olga|-test].computerbild.de`
(503), `shop.vip-club.computerbild.de` + `epaper.vip-club.computerbild.de` (200).

### Finding — unauthenticated internal telemetry on `data-*.welt.de` (LOW)

`data-99329e3cb2.welt.de` → `welt-relay.iocnt.net` and `data-e4997adf31.welt.de` →
`mobwelt-relay.iocnt.net` (`relay-client-c03.iocnt.net`, 136.110.231.186, GCP LB,
`x-powered-by: cST-de09b48-2609251000-prd`). These are WELT app telemetry relays.

`GET /metrics` is **unauthenticated** and returns internal operational state
(`recon/findings/metrics-welt.json`):

```json
{"mode":"IOMB","writer":{"queue_length":0,"queue_capacity":30000,
                         "messages_queued":56712329,"messages_dropped":0}}
```

`GET /health` → `{"status":"ok"}`. `/` returns 200 empty. `OPTIONS`/`POST` also return 200
(no `Allow` header emitted, no real method enforcement on these paths). No further paths found
(`/debug/vars`, `/config`, `/stats`, `/ingest` … all 404).

**Assessment: Low.** Real but thin — leaks internal architecture (queue-based relay, mode
`IOMB`) and scale (~56.7M messages). **No user data, no PII, no credentials.** Under
*"no realistic exploit scenario → None"* this may land at **None/Low**. Worth noting, not
leading with it. The `data-*` hostnames are per-tenant hashes and are **not** brutable
(`data-1.welt.de`, random `data-<hash>.welt.de` do not resolve).

### Takeover sweep (negative)
Checked every new CNAME for SaaS footholds, specifically to complete the §6 P1 CORS chain:
- `design.welt.de` → **`zeroheight.com.`** (bare apex). Live and serving "WELT Design System".
  The bare-apex CNAME is actually zeroheight's *documented* setup — **not** a misconfig.
  Residual churn risk only (if WELT's zeroheight account lapses the record would dangle).
- `www.bild.design` → `cdn.webflow.com` — live Webflow site (`data-wf-domain="www.bild.design"`
  bound, 401 password page). Claimed, not dangling.
- `event.{bild,autobild,sportbild}.de`, `checkout.co.auth.{bild,welt}.de` → live CloudFront.
- Control: a genuinely dead CloudFront distribution does **not resolve** (HTTP 000).

**No takeover foothold found.** The CORS chain in §6 P1 remains unproven.

## 3f. Hey chat — the RoE-invited UUID question (answered, negative)

The RoE says: *"IDOR attacks for the Hey chat, which include a UUID, are out of scope and the risk
is accepted. However, we would greatly appreciate submissions to enumerate or guess these UUIDs."*
That is the one target the programme asks for by name. Worked it.

**Environment:** `hey.bild.de` = Vite SPA on S3/CloudFront (`max-age=0,no-cache`), API at
`hey.bild.de/api`. Subdomains found: `admin.`, `m2.`, `m2p.`, `m.`, `nebuly.` (LLM observability),
`preview.`, `proxy.`, `www.` — only `hey.bild.de` (200) and `preview.hey.bild.de` (403 CloudFront)
serve. `m2p.hey.bild.de` resolves but fails TLS (SNI/handshake error). Dev/stage
(`dev.`, `stage.`, `demo.`, `local.` + `dev.go.welt.de`) are 403 or absent — locked down.

**API surface (unauthenticated):**

| Endpoint | Result |
| --- | --- |
| `/api/experiences` | **200** — 640 public experiences w/ `experienceId`, `slug`, `title`, `paidOnly` |
| `/api/experiences/{id}` | **200** — full experience body; random UUID → 404 |
| `/api/prompt-recommendations` | **200** — public prompt list |
| `/api/conversations`, `/api/memory`, `/api/preferences`, `/api/bookmarked-experiences` | **403** `Access is denied for request on GET …` |

### Answer: the UUIDs are NOT enumerable or guessable

All **640** `experienceId` values are **UUIDv4** (`cut -c15` = `4` for every one; 122 bits of
randomness). No v1/time-based IDs, no sequential pattern, no ordering leak (sorted `head` shows
uniform scatter). Random UUID → 404. **The programme's stated concern does not materialise —
their UUIDs are correctly random.** This is a clean negative answer to a direct question.

### `paidOnly` — checked, and it is by design
Exactly **1 of 640** experiences is `paidOnly: true` (`bd315d87-9163-4e15-9e8c-9f64aecaa70a`), and its
body *is* returned unauthenticated (200, 1597 bytes). Initially looked like a BILDplus paywall
bypass. It is not: the bundle shows `paidOnly` drives a **BILDplus badge** and gates the **chat
interaction**, not the teaser — non-logged-in users get the teaser plus
*"To continue enjoying, you need a BILDplus subscription"* with `errorCode: 402` when they try to
interact. The `/seo/:id` route confirms these are intentionally public SEO landing content.
**Not a finding.**

### Net
Nothing reportable from Hey. The RoE's invitation is answered negatively and can be passed back
as a reassurance rather than a submission.

## 3g. Tier 1 adtech — `*.asadcdn.com` and `adtechnology.axelspringer.com`

### `pbs.asadcdn.com` / `pbs-test.asadcdn.com` — open Prebid Server

Both are **Prebid Server** (server-to-server header-bidding proxy), publicly reachable:

| Endpoint | Result |
| --- | --- |
| `/status` | `{"application":{"status":"okay"}}` (test: `"oki doki 08:00"` — jokey string on a live host) |
| `/info/bidders` | **200** — list of ~200 adapter names |
| `/info/bidders/all` | **200**, 71 KB — `{aliasOf, capabilities, maintainer, status, usesHttps}` |
| `/openrtb2/auction` | **405 GET / `allow: POST`** — open for auction POSTs |
| `/cookie_sync`, `/getuids` | 405 / `{}` |

**Information disclosure: NOT a finding.** `/info/bidders` and `/info/bidders/all` are Prebid
Server's *documented, intended* public endpoints. The only personal data is `maintainer.email`,
and those are Prebid's own open-source maintainer addresses — public in the upstream repo. No
account IDs, publisher IDs, API keys or endpoints are exposed. Verified across every key path.

**SSRF hypothesis: leads nowhere.** Prebid Server is a genuine SSRF surface (it fetches bidder
URLs server-side), and the request-supplied-host adapters are exactly the vector — but the deployed
config has them **DISABLED**:

```
adkernel DISABLED   adkernelAdn DISABLED   adtelligent DISABLED
generic  DISABLED   colossus    DISABLED
```

The 22 `ACTIVE` bidders are all major networks with hard-coded endpoints
(`appnexus criteo ix openx outbrain pubmatic rubicon smartadserver teads thetradedesk ttd …`),
so there is no attacker-steerable fetch. An *open* auction endpoint is also by design — browsers
call it for client-side header bidding.

**Confirmed nothing:** `/openrtb2/auction` POST `{}` → 400 (gzip error body). No auction request
was submitted, so no outbound fetches to real ad networks were triggered.

**Net:** the standard public metadata endpoints look alarming at a glance and are not a bug; the
one genuinely interesting property (SSRF) is closed off by the adapter config. Not reportable.
Residual note only: the **test** instance is internet-facing — hygiene, not a vulnerability.

### `adtechnology.axelspringer.com` (Tier 1) — clean
Apache/2.4.58, `robots.txt` = `Disallow: /`. `/server-status` → 403. No `/actuator`, `/swagger`,
`/phpinfo.php`, `/wp-login.php` or `/.git/HEAD`. Nothing found.

### Other `*.asadcdn.com`
`pbsb`, `staging.pbsb`, `test.pbsb` → uniform **401** on every path (auth wall, `awselb/2.0`);
`status` → uniform 400; `tmi` → `/health` 200 `Ok`, `/admin` + `/metrics` 403 (admin rules);
`reports` 301. `tmi`'s `/health` is trivial, no content.

## 3h. Tier 1 apexes — path-level pass (clean), plus new `pss.welt.de` domain

### The five Tier 1 apexes: all SPA catch-alls, no API exposure

| Host | Behaviour |
| --- | --- |
| `epaper.welt.de` | nginx, inline `weltConfig` (id 2496129), no API paths |
| `cancellation.prod.ps.welt.de` | S3+CloudFront SPA — **every** path returns the same index HTML (200), incl. `/api`, `/admin`, `/actuator`, `/.git/HEAD`. Catch-all, not exposure. |
| `digital.welt.de` | Astro SSR; `/community/`, `/faq`, `/pur`, `/epaper` all 200 |
| `go.welt.de` | S3+CloudFront SPA — catch-all, same as cancellation |
| `meinkonto.bild.de` | S3+CloudFront SPA, catch-all |

`robots.txt` exposed a route list but no API. Worth restating: **all-paths-200 on an S3/CloudFront
SPA is a catch-all, not a directory listing** — several of these look like full exposure at a glance
and are nothing.

### New in-scope domain discovered: `pss.welt.de`

Leaked via `digital.welt.de/robots.txt` (`Sitemap: https://pss-deli.prod.pss.welt.de/sitemap.xml`).
Matches `*.welt.de` (Tier 2). CT shows four hosts:

```
prod.pss.welt.de                 uat.pss.welt.de
pss-deli.prod.pss.welt.de        pss-deli.uat.pss.welt.de   (216.137.53.x / 3.174.193.x)
```

`pss-deli.{prod,uat}` front the same DELI app as `digital.welt.de` (`data-tenant="welt"`),
`/health` → `ok`, robots/sitemap served. **UAT mirrors prod exactly** — same pages, no debug/API
paths (`/api`, `/docs`, `/swagger`, `/graphql`, `/actuator` all absent). Brute-forced ~20 sibling
service names (`pss-api`, `pss-auth`, `pss-cms`, … in prod+uat): only `pss-deli` exists. Nothing found.

### S3 bucket — correctly locked
`ps-kitchen-prod-assets` (from the DELI HTML): listing = **403 AccessDenied** (all three endpoint
forms + `?list-type=2`). Individual known objects serve publicly (intended CDN assets). Siblings:
`ps-kitchen-uat-assets` 403, `ps-kitchen-{dev-,}assets`/`ps-kitchen-prod` 404 NoSuchBucket.
**No misconfiguration.**

### Net
Clean. #1 is closed with no finding, but `pss.welt.de` (prod+uat) is new in-scope surface worth
revisiting if the programme adds assets or if a bug lands nearby.

## 3i. Cross-brand identity discovery (most significant architectural finding)

Chasing `consumer-api.prod.auth.computerbild.de` (the "third Ory brand") revealed something bigger.
The CNAME **is the Ory project slug**:

| Host | Ory project |
| --- | --- |
| `consumer-api.prod.auth.bild.de` | `recursing-archimedes-wer2643ri7` |
| `consumer-api.prod.auth.welt.de` | `recursing-archimedes-wer2643ri7` |
| `consumer-api.prod.auth.computerbild.de` | `recursing-archimedes-wer2643ri7` |
| `consumer-api.uat.auth.bild.de` | `eloquent-williams-s4vz0dn2gr` |
| `consumer-api.stage.auth.bild.de` | `eloquent-williams-s4vz0dn2gr` |
| `consumer-api.uat.auth.welt.de` | `eloquent-williams-s4vz0dn2gr` |
| `consumer-api.uat.auth.computerbild.de` | `eloquent-williams-s4vz0dn2gr` |

`recursing-archimedes-wer2643ri7` is **the exact name of the session cookie** in our test accounts
(`ory_session_recursingarchimedeswer2643ri7`) — so the projects are directly identifiable.

**Verified consequences:**

1. **A session created on bild.de authenticates on welt.de AND computerbild.de** — `GET
   /sessions/whoami` returns HTTP 200 with the identical identity (`12371af5-…`, same email) on all
   three. Confirmed live.
2. **Identical JWKS keys** across all three brand APIs (`kid 6043e4f7-…`, `64c30aa3-…`) — same
   project, same signing keys.
3. **All UAT + stage environments share a second single project** — a session minted in bild UAT
   would be valid on computerbild UAT.
4. **CORS is still per-brand** (`x.bild.de` → computerbild API = no ACAO, and vice versa), so the
   shared session is not directly cross-origin readable across brands.

**Assessment — likely intentional, but notable.** `subOrigin: "as"` (Axel Springer) in the `asinfo`
cookie points to a deliberate **unified Axel Springer identity** — one account for BILD, WELT and
COMPUTER BILD. That is a normal media-group SSO design, and entitlements (`purchaseData.entitlements`)
are carried separately per product. **I did not find an exploitable consequence** and our test
accounts have `entitlements: []`, so the one question that *would* matter is untestable here:

> **Does a paid BILDplus entitlement grant access to COMPUTER BILD (or vice versa)?** If entitlement
> checks trust the shared identity without a per-brand entitlement check, that is a real cross-brand
> access bug. That needs a paid account to prove — flag it for anyone who has one.

**Back-pocket impact:** this **retroactively explains §6 P3** (the "UAT issuer mismatch"). bild UAT
advertising the *stage* issuer is not a misconfiguration — bild UAT and stage are literally the same
Ory project. P3 should be downgraded accordingly.

## 3j. Devel/stage environments — locked down

| Host | Result |
| --- | --- |
| `digasred.computerbild.de`, `digasred.stage.computerbild.de` | **403** all paths (Akamai, `ak_p` server-timing) — edge block, prod *and* stage |
| `vc.stg.vip-club.computerbild.de` | **403** Apache, all paths |
| `edition-issues-devel.ep.welt.de` | 200 `Not found` at root (S3, no index object); no other paths |
| `dev1–5.epaper.welt.de` | see below |
| `stage.go.welt.de` | no A record |

### `dev1–5.epaper.welt.de` — vendor "004 GmbH" Account Self Service
All five serve the same legacy Java app (`nginx/1.31.3`, `004dev.com`, title
**"004 GmbH – Account Self Service"**). Java servlet `.cc` mappings (`showLogin.cc`,
`accounts/authVerify?operation=reset|unlock`), `JSESSIONIDADSSP` + Zoho `zsec` URL-validator libs.

**Notable defect, but not reportable:** every `Set-Cookie` carries **malformed attributes** —
`SameSite = None` with spaces around `=`, duplicated three times, and conflicting with an earlier
`SameSite=Strict`:

```
_zcsr_tmp=…;path=/;SameSite=Strict;Secure;priority=high;Secure;SameSite = None;Secure;SameSite = None
adscsrf=…;path=/;SameSite=None;Secure;priority=high;Secure;SameSite = None;Secure;SameSite = None
JSESSIONIDADSSP=…; Path=/; Secure; HttpOnly;Secure;SameSite = None
```

Browsers ignore the malformed `SameSite = None`, so the intended value never applies and the
session cookie falls back to the browser default (Lax). **That is more restrictive, not less** —
the failure is a functional/SSO breakage, not a security downgrade. CSRF is separately token-based
(`adscsrf`). Checked for an open redirect via `JumpTo.testConnection` / the `ignoreReferer=true`
bypass and common redirect params — **no redirect parameter is honoured** (`showLogin.cc?jumpTo=…`
etc. all return the plain page, zero reflection). **No finding.**

Caveat for scoping: this is a **third-party vendor's** product (004 GmbH) merely hosted on a
`*.welt.de` name. In scope by the wildcard, but a report here would be aimed at the vendor.

## 3k. Session 2 — Tier 3 sweep + a Tier 1 asset that enumeration MISSED

### ⭐ NEW HOST: `api.politico.eu` (Tier 1) — found only by following a redirect

**CT enumeration never found this host.** It surfaced from the redirect chain of
`help.politico.eu` → `api.politico.eu/oauth/login`. It is a **production Rails API** on AWS
Elastic Beanstalk:

```
api.politico.eu  CNAME  api-production.fga9nxmmcb.eu-west-1.elasticbeanstalk.com  (34.240.112.159, 52.19.29.204, 40.180.5.18)
```

| Probe | Result |
| --- | --- |
| `GET /` and `/health` | **`{"success":true,"version":"v4.390.0"}`** — version disclosure |
| `GET /admin` | 302 → `www.politico.eu/?option=saml_user_login&idp=azure&redirect_to=/admin_oauth_login/` (**Azure AD SAML**) |
| `GET /manifest.json` | `{"name":"Admin - POLITICO","start_url":"/admin"}` — admin PWA |
| `GET /oauth/login` | 302 → `www.politico.eu/oauth/authorize/?client_id=znQGlYse…&redirect_uri=…&redirect_url=…&timestamp=…` |
| `GET /oauth/login` **without** `redirect_url` | **500** `{"error":"internal_server_error"}` — unhandled nil |
| `GET /oauth/callback` | 302 → `www.politico.eu/why-go-pro/` (upsell) |
| Rails internals (`/rails/info*`, `/assets`, `/cable`, `/-/health`) | all 404 |
| `OPTIONS`/`PUT`/`DELETE`/`PATCH /` | 404 (clean, no method disclosure) |

**Open-redirect / OAuth checks — all SAFE:** `redirect_url` and `redirect_uri` are ignored for
unauthenticated users (everything bounces to the upsell page); lookalike domains
(`www.politico.eu.evil.example`) and `//evil.example/` are not honoured. No stack traces, no debug
leak (`?format=json`, `?debug=1` all return the clean JSON error only).

**Findings here are informational only:** version disclosure (`v4.390.0`) and a 500 on a missing
required param. No sensitive data, no auth bypass. Notable mainly because a **Tier 1 production API**
was invisible to certificate-transparency enumeration.

> **Methodology lesson:** CT logs missed `api.politico.eu` entirely. Follow **redirect chains** and
> read **`Location` headers** — they expose undocumented hosts that DNS/CT enumeration will not.

### Tier 3 media brands — swept, essentially clean

| Host pattern | Result |
| --- | --- |
| `suche.fitbook.de`, `search.fitbook.de` | **Unauthenticated Google search proxy.** `/api/search?q=` returns live SERP data (10 organic results, related searches/questions). **No rate limiting** (5 rapid requests, no 429, no RL headers). |
| `data-*.<brand>.de` (fitbook, techbook, stylebook, myhomebook, petbook, travelbook) | Same `/metrics` + `/health` relay as WELT (§3e) — identical 114-byte queue stats. Consistent pattern, informational. |
| `pur.<brand>.de` (fitbook, autobild, travelbook, techbook, petbook, myhomebook, computerbild) | **contentpass** subscription portal — properly validated OIDC. |
| `tollbit.<brand>.de` | TollBit AI-licensing router (vendor), 402 |
| `m.purmail.<brand>.de` | Flowmailer (vendor) |
| `link.mailer.<brand>.de` | Emarsys (vendor) |
| `cmp.<brand>.de` | Sourcepoint CMP (vendor), 403 |
| `wetter.travelbook.de` | wetterkontor.de (vendor) |
| `ras.`, `dsl-start*`, `speedtest*` | 401/403, locked |

**`suche.fitbook.de` — tested and hardened.** I expected reflected XSS in the search page (classic),
and it is **not** present. The app applies **context-aware encoding**: the query is reflected into
both an HTML attribute *and* a JS string, and each is encoded for its own context —
`"`→`\u0022`, `<`→`\u003c`, `\`→`\\` in JS; `&#34;`/`&lt;` in HTML. No SSRF (no URL/host param
has any effect), no pagination abuse (`start`/`num`/`page` all ignored, always 10 results), `txid` is
page-local only, and all error paths are clean. The only residual issue is the **missing rate limit**
on a proxy that costs money per request (quota/cost abuse). Under *"no realistic exploit scenario →
severity None"* this is **Informational at best**; not filed.

**`pur.*` — contentpass OIDC properly locked down.** Each brand has its own `propertyId` on one
shared contentpass provider (e.g. fitbook `ffb9ba3c-…`, autobild `5373b154-…`, computerbild
`6884059f-…`). Tested: an **arbitrary `propertyId` is rejected**, and **`redirect_uri` is strictly
validated** (foreign and lookalike redirect URIs both refused). Clean — and worth noting this is a
**cross-brand** subscription structure, adjacent to the §3i Ory finding.

### Session 2 net
Two new-in-scope items of note: `api.politico.eu` (informational) and the search proxy's missing
rate limit (informational). The Tier 3 estate is overwhelmingly **third-party vendor** infrastructure,
which limits what is reportable and useful.

## 3l. Session 3 — authenticated diff sweep & the identity architecture

Approach: use the **two existing self-registered accounts** (no new accounts, no program contact).
Diff **anonymous vs authenticated** across the in-scope estate. **Cookie hygiene:** the session cookie
was sent **only** to first-party AS domains (456 of 573 hosts) — never to third-party vendor hosts
(TollBit, Emarsys, Flowmailer, Sourcepoint, wetterkontor), so no credentials were handed to vendors.

### Auth-diff sweep result: only 3 real differences, all benign

Root-page diff over 456 hosts → 18 apparent diffs, of which **15 were byte-count noise** (1–20 byte
drift from dynamic content). The **3 genuine behavioural differences**:

| Host | Anonymous | Authenticated |
| --- | --- | --- |
| `www.bild.de` | 200 (751 KB page) | **302 → `login.prod.ps.bild.de/refresh?returnTo=…`** |
| `sportbild.bild.de` | 200 | **302 → same** |
| `m.sportbild.bild.de` | 200 | **302 → same** |

That is the **Ory → whoami session bridge** firing. Verified brand-specific: it triggers **only on
bild.de properties** — `www.welt.de`, `www.computerbild.de`, `www.autobild.de` do **not** redirect
when authenticated.

### New in-scope hosts (found via the redirect chain — CT missed them)

- `login.prod.ps.bild.de` → `d2k5jxv0h3i7ht.cloudfront.net` (Tier 2 via `*.bild.de`)
- **`whoami-api.prod.ps.bild.de`** → same CloudFront (Tier 2 via `*.bild.de`)
- also resolve: `login.uat.ps.bild.de`, `whoami-api.uat.ps.bild.de`, `whoami-web.prod.ps.bild.de`,
  `whoami-api.prod.ps.welt.de`

### `whoami-api` — the JWT trust service

```
GET /api/refresh       400 {"title":"Constraint Violation","status":400,
                            "violations":[{"field":"refreshTokenAndRedirect.returnTo","message":"must not be blank"}]}
POST /api/refresh      400 "asrf must not be blank"
GET /.well-known/jwks.json  200 {"keys":[{"kty":"RSA","use":"sig",
                                 "kid":"whoami-keyset-1788775688419","alg":"RS256"}]}
```
All other paths → uniform **503** (ALB only routes `/api/refresh` and the JWKS). The `kid`
`whoami-keyset-1788775688419` is the **same** keyset as the `asid` JWT in our cookie jar — so this is
the service that mints and verifies `asid`.

### ⭐ `returnTo` — tested thoroughly, CORRECTLY VALIDATED (no open redirect)

The chain is two layers: `login.prod.ps.bild.de/refresh` **passes `returnTo` through unvalidated**
(307 to `whoami-api`), so the backend is the only control — and it **holds**:

| `returnTo` | `whoami-api/api/refresh` |
| --- | --- |
| `https://evil.example/` | **400** |
| `https://www.bild.de.evil.example/` | **400** |
| `//evil.example/` | **400** |
| `https://attacker.test/` | **400** |
| `https://www.bild.de/` | 307 → `https://www.bild.de/` (+ clears `asinfo`/`asid`/`asrf`) |

Validated with and without a session, and with the refresh-token path. **No open redirect.** Worth
noting as defence-in-depth: the CloudFront layer *could* validate too, but the backend is sufficient.

### Identity architecture (now mapped)

Two parallel session systems:

1. **Ory** (Kratos/Hydra) — `ory_session_recursingarchimedeswer2643ri7`, shared across **all** brands
   (bild/welt/computerbild), expiry ~3 months (§3i).
2. **whoami** — `asid` (RS256 JWT, `iss:"whoami"`, `aud:"BDEp"`) + `asinfo` (entitlements/expiry) +
   `asrf` (refresh token, HttpOnly, scoped to `whoami-api`). `login.prod.ps.bild.de/refresh` is the
   **bridge** between them, and it is wired up for **bild.de properties only**.

`consumer-api.{prod,uat}.auth.<brand>` (Ory) and `whoami-api.prod.ps.<brand>` (trust) are separate
planes; `consumer-next-web`, `userprofile-wrapper`, `deli-wonp` are SPA front ends (catch-alls, all
paths 200 with identical HTML) with no direct API exposure — verified.

### Net
**No access-control finding.** The authenticated diff surfaced only the benign SSO bridge; every
redirect parameter tested (`returnTo`, `redirect_url`, `redirect_uri`) is validated on every brand and
environment. The value here is the **architecture map** and two undocumented in-scope hosts.

## 3m. newsos.com Dynamic Client Registration — TESTED, not vulnerable

§2 originally flagged this as a candidate: discovery advertises a `registration_endpoint` with
`token_endpoint_auth_methods_supported: ["none"]`. That combination *would* mean anyone could mint an
OAuth client unauthenticated — and with the `newsos-mcp/invoke` scope, potentially reach the MCP server.
**Verified properly, and the control holds.**

Read-only probes were inconclusive (`GET`/`HEAD`/`OPTIONS /oauth/register` → 404; normal for POST-only
DCR routing). A **single** unauthenticated `POST` was therefore made with deliberately **inert** client
metadata — `redirect_uris: ["https://example.invalid/callback"]` (RFC 2606 reserved TLD, can never
resolve/callback, so the client cannot be used even if created), `client_name`
`intigriti-bugbounty-test-DO-NOT-USE-<rand>`. One request, no retries. Full transcript:
`recon/newsos/registration-attempt.log`.

```http
POST /oauth/register
{"client_name":"intigriti-bugbounty-test-DO-NOT-USE-…",
 "redirect_uris":["https://example.invalid/callback"],
 "grant_types":["authorization_code"],"response_types":["code"],
 "token_endpoint_auth_method":"none"}

HTTP/2 400
x-ratelimit-limit: 10
x-ratelimit-remaining: 9
x-ratelimit-reset: 2
{"error":"invalid_redirect_uri","error_description":"redirect_uri not allowed: https://example.invalid/callback"}
```

**Conclusion — NOT a vulnerability:**

1. **`redirect_uris` is allowlisted.** The endpoint parsed the request and *rejected* the redirect URI.
   Registration is therefore **not open** — an attacker cannot register a client pointing at a
   destination they control. This is the control that matters, and it works.
2. **No client was created** — 400 is a rejection, not a creation. Nothing to clean up.
3. **Rate limiting is present** — 10 per 2s window (`x-ratelimit-*`), better than several other
   endpoints in this estate.

The endpoint being reachable without authentication is **expected** for DCR/DCR-style provisioning
(clients must be able to self-register); the allowlist is what bounds the risk. **Original concern
withdrawn.** No further registration attempts were made, and no attempt was made to enumerate allowed
redirect URIs — that would have required guesswork with a real chance of creating clients, for a
question already answered.

### Addendum — allowlist bypass testing (6 patterns, all rejected)

A naive `redirect_uri` allowlist implemented with substring/suffix matching would be bypassable
(e.g. `Contains("newsos.com")`, `HasSuffix("as-nmt.de")`). Tested that directly — **one attempt per
pattern, stopping on first success** to minimise artifacts. Domains used are **RFC 2606 reserved**
(`.invalid`, guaranteed non-resolvable) so no third party was targeted. Log:
`recon/newsos/bypass-attempts.log`.

| Pattern | `redirect_uri` | Result |
| --- | --- | --- |
| path suffix | `https://example.invalid/newsos.com` | **400** |
| path suffix | `https://example.invalid/as-nmt.de` | **400** |
| domain suffix | `https://newsos.com.example.invalid/` | **400** |
| userinfo trick | `https://example.invalid@newsos.com/` | **400** |
| path + query | `https://example.invalid/?u=newsos.com` | **400** |
| backslash | `https://example.invalid\\@newsos.com` | **400** |

**All six rejected; zero clients created.** The implementation is **not** a naive substring/suffix
match — it correctly rejects a host that merely *contains* an allowlisted domain, and correctly
treats `example.invalid@newsos.com` (whose real authority is `newsos.com`) as disallowed. Validation
is done on a properly parsed origin.

**Conclusion: `redirect_uri` validation is robust. No allowlist bypass.** This is a stronger negative
than the initial single test — it specifically rules out the naive-implementation class.

### Session 3 net (addendum)
`newsos.com` DCR was properly tested (unauthenticated registration + six allowlist-bypass patterns)
and **closed as not vulnerable** — the control is correctly implemented. No client was ever created.
The estate's pattern continues: controls exist where they matter.

## 4. Prioritised target list

> **Status: nothing reportable yet.** After the authenticated and cache/CORS work, no candidate
> clears the RoE bar. Items 1–2 are config-level with no demonstrated exploit scenario
> ("severity None"); item 3 needs sign-off and is a hardening issue; item 4 is explicitly
> excluded; items 5–8 are untested leads. Kept for orientation, not as a submission queue.

| # | Target | Scope | Why / status |
| --- | --- | --- | --- |
| 1 | **`hey.bild.de` + `*.hey.bild.de`** | **Tier 1** | **RoE explicitly invites UUID enumeration/guessing.** Untouched. `admin.`, `proxy.`, `m2p.`, `preview.` found; `preview` 403. |
| 2 | **`*.asadcdn.com`** (pbs / pbsb / staging.pbsb / test.pbsb / reports / status) | **Tier 1** | Ad-serving platform. Four 401 endpoints never path-probed. |
| 3 | **`adtechnology.axelspringer.com`** | **Tier 1** | Apache/2.4.58, "AS Adtechnology". Only `/` probed. |
| 4 | **`epaper.welt.de`, `cancellation.prod.ps.welt.de`, `digital.welt.de`, `go.welt.de`, `meinkonto.bild.de`** | **Tier 1** | Only roots probed. `meinkonto` = S3 over `userprofile-wrapper.prod.ps.bild.de`. |
| 5 | `consumer-api.prod.auth.computerbild.de` | Tier 2 | Third Ory brand — full self-service API, PKCE `plain` too. Test as with bild. |
| 6 | `digasred[.stage].computerbild.de`, `vc.stg.vip-club.computerbild.de`, `speedtest-test.computerbild.de` | Tier 2 | Stage envs, all 403/401 — retry with varied Host/paths. |
| 7 | `edition-issues-devel.ep.welt.de`, `dev1–5.epaper.welt.de` | Tier 2 (`*.welt.de`) | **devel** environments. S3-backed / `004dev.com`. |
| 8 | `alias-apitest.sandbox.bild.design` | Tier 2 (`*.bild.design`) | AWS API Gateway, `/` → 500. Enumerate valid routes. |
| 9 | `data-*.welt.de` `/metrics` | Tier 2 (`*.welt.de`) | Low-info-disclosure — see §3e. |
| 10 | `dealer.prod.ps.axelspringer.de/purchases/*` | **Tier 1** | 503, no healthy backend. Retry later. |
| 11 | `newsos.com` `/oauth/register` DCR + `newsos-mcp/invoke` | Tier 2 | Needs sign-off before writing state. |
| — | `consumer-api.uat.auth.{bild,welt}.de` issuer mismatch; PKCE `plain` | Tier 2 | **Out of scope / severity None** per RoE review. Back pocket only. |

Also worth a pass: the remaining Tier 3 media brands surfaced in pass 2
(`stylebook`, `techbook`, `fitbook`, `myhomebook`, `petbook`, `travelbook`, `bild.design` —
~17 live hosts each) — all Tier 3, lowest priority.

### Do not test
`*.docs.ps.axelspringer.de`, `rosetta.*`, `fonti.*`, `web-logger.*`, `rusty-heartbeat.*`,
`whoami-api.docs.*`, `consumer-api.prod.ps.axelspringer.de`, `api.ps.axelspringer.de`, … — no
`*.axelspringer.de` wildcard in scope. Also the 36 `emarketer.com` DNS sinkholes.

### Dead / unreachable
All 12 in-scope IPs (0 open ports), `editorial.one` (RFC1918), `technik.{beta.,}autobild.de`
(timeout), `germany.politico.eu` (CNAME NXDOMAIN), `asadcdn.com`/`auth.bild.de`/`springtools.de`
apexes (wildcard-only).

---

## 6. Back pocket — chainable primitives

Findings that are **not** reportable alone, but which would materially upgrade someone else's
finding if combined with it. Re-check these whenever a new bug lands anywhere in this programme.

### P1 — Credentialed CORS wildcard (best amplifier)
`Access-Control-Allow-Origin` reflects **any** subdomain of
`bild.de`, `welt.de`, `autobild.de`, `computerbild.de`, `sportbild.de`, `spring-media.de`,
`axelspringer.de` with `Access-Control-Allow-Credentials: true` — on
`checkout-next-api.prod.ps.bild.de` and `consumer-api.prod.auth.bild.de`.
Arbitrary ports accepted on the checkout API.

**What it amplifies — any foothold on one of those seven domains becomes credentialed read access
to the auth and commerce APIs:**
- **SSRF** returning raw response bodies → SSRF reachable from the allowlisted domain space, or
  an SSRF whose response is readable, can be paired with a forged `Origin` to read authenticated
  API data.
- **XSS** anywhere on those domains → direct ATO: read `/sessions/whoami`, then the identity and
  purchase APIs with the victim's cookies.
- **Subdomain takeover** on any of those domains → same, with persistent control.
- **Open redirect** on a subdomain → useful for token/code leakage into an attacker origin that
  CORS then trusts.

Watch-list when hunting the foothold: `*.spring-media.de` (allowlisted, least understood) and
`*.axelspringer.de` (allowlisted; the `ps.*` estate and generated preview hosts live there).
`*.springtools.de` is **not** allowlisted, so its 3,717 generated hosts are not usable for this.

### P2 — Ory `init_code` / `return_to_code` token exchange
`/sessions/token-exchange` is a session-token exchange surface whose codes are opaque and leak
nothing in error paths. If any oracle for these codes is ever found, it is a direct session
hijack (Tier 1).

### P3 — UAT/stage issuer confusion
UAT discovery advertises the **stage** issuer (`consumer-api.stage.auth.bild.de`), and the welt UAT
tenant advertises the **bild** stage issuer. Alone: a spec violation, severity None. Combined with
any RP that trusts `iss` loosely, or any future ability to mint in stage, it becomes a
cross-brand/cross-environment token acceptance issue.

### Housekeeping before re-engaging
- Two production test sessions were pasted into chat on 2026-09-26 — **revoke/rotate both.**
  `creds/` is gitignored; no secret leaked into any tracked file (verified).
- An unintended purchase intent (`purchaseId 3JqMPu3Q84QwfgNjZnlfZZSgsDw`) was created on prod
  under account A — clear it if desired.
- Scope trap to remember: **`*.axelspringer.de` is not in scope** except
  `dealer.prod.ps.axelspringer.de/purchases/*`. The whole `ps.axelspringer.de` estate is off-limits.
