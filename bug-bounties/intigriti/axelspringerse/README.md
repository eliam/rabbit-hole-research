# Axel Springer SE / AS National Media & Tech — Intigriti Engagement

**Programme:** `axelspringerse` (Intigriti, public/open, Media & Entertainment)
**RoE source:** `axelspringerse.RoE` — extracted to `scope.md`
**Dates:** 2026-09-26 (recon + testing)
**Status:** ✅ **CLOSED / SIGNED OFF.** Recon complete, one candidate finding, every other surface tested.

**Constraints applied at sign-off:** no programme contact, no requests for test accounts, no new accounts
beyond self-registration. Work was done with **unauthenticated access + two self-registered accounts** only.

---

## TL;DR

- Enumerated the whole in-scope estate: **5,002 subdomain names**, 428 resolving, **336 live endpoints**;
  later passes found **~200 more live endpoints** plus **4 undocumented in-scope hosts** that CT missed.
- Cleared **every Tier 1 asset** (two are unavailable/dead).
- **One candidate finding:** internet-exposed, unpatched **ManageEngine ADSelfService Plus (build 6519)**
  on `dev1–5.epaper.welt.de` → `finding-adssp-dev1.md`.
- **One back-pocket amplifier:** credentialed **CORS wildcard** across 7 parent domains → `recon-findings.md` §6 P1.
- **Everything else held up** — and it was *tested*, not assumed. Six separate leads that looked exploitable
  were each properly investigated and correctly controlled (see §3.4 / §3m). The negative results are the
  bulk of the value here.
- **No submission was filed** — signed off as complete without programme contact.

---

## 1. Programme & scope

Full extraction in **`scope.md`**. Essentials:

- **Tiers:** Tier 1 (most valuable) → Tier 3. Bounties €15–€2,500 by CVSS band.
- **Worst-case scenarios the programme cares about:** (1) publishing fake news, (2) obtaining sensitive
  user data, (3) command execution on production services.
- **Explicit invitations** (RoE lines 690–694):
  - *"For the authenticated endpoint, we only accept cache poisoning submissions that are valid with
    changing authentication headers."*
  - *"IDOR attacks for the Hey chat... are out of scope... However, we would greatly appreciate submissions
    to enumerate or guess these UUIDs."*
- **Key exclusions:** `*.axelspringer.com`; CORS misconfig on *non-sensitive* endpoints; session
  non-invalidation; username/email enumeration; MITM/physical/compromised-account attacks;
  *vulnerabilities without a realistic exploit scenario get severity "None"*; **no PoC = not considered**.

### ⚠️ Scope trap — remember this
**`*.axelspringer.de` is NOT in scope.** No such wildcard exists. The only in-scope `axelspringer.de` path is
`dealer.prod.ps.axelspringer.de/purchases/*`. That means the entire **`*.ps.axelspringer.de` estate**
(`*.docs.ps.*`, `rosetta.*`, `fonti.*`, `web-logger.*`, `rusty-heartbeat.*`, `whoami-api.docs.*`, ~30 hosts)
is **off-limits** — it looks like the juiciest thing in the engagement and it is not authorised. The same
infrastructure under **`ps.bild.de` / `ps.welt.de` IS in scope** via the Tier 2 `*.bild.de` / `*.welt.de`
wildcards.

---

## 2. What was done

| Phase | Action | Output |
| --- | --- | --- |
| 1 | Scope extraction from RoE | `scope.md`, `targets.txt`, `ip-ranges.txt` |
| 2 | DNS + HTTP liveness, 39 apex assets | `dns-resolved.tsv`, `http-final.tsv` |
| 3 | In-scope IP range port scan | `logs/nmap-iprange.txt` — **0 open ports on all 12** |
| 4 | CT subdomain enumeration (pass 1) | `crt-subdomains.txt` — 4,467 names |
| 5 | Resolution + HTTP probe | `resolved.tsv`, `live-endpoints.tsv` — 336 live |
| 6 | Ory auth stack mapping + authenticated testing | `recon/flows/`, `authtest.sh` |
| 7 | Cache/CDN + CORS testing | `recon-findings.md` §3d |
| 8 | **CT pass 2** — fixed a major silently-failed gap | `crt-all.txt` — 5,002 names; +200 live |
| 9 | Hey chat / RoE-invited UUID analysis | `recon/hey/` |
| 10 | Tier 1 apexes + adtech path-level | `recon-findings.md` §3g/§3h |
| 11 | ADSSP discovery + CVE correlation | `finding-adssp-dev1.md` |
| 12 | Tier 3 sweep + `suche`/`pur`/search analysis | `recon-findings.md` §3k |
| 13 | **Found `api.politico.eu`** — Tier 1 API that CT enumeration missed | `recon-findings.md` §3k |
| 14 | Anon-vs-authenticated diff sweep (456 hosts, 2 existing accounts) | `recon-findings.md` §3l |
| 15 | **Found `login.prod.ps.bild.de` + `whoami-api.prod.ps.bild.de`**; mapped identity architecture | `recon-findings.md` §3l |
| 16 | `newsos.com` DCR — tested + **6 allowlist-bypass patterns** | `recon-findings.md` §3m |

> **Methodology lesson from phase 8:** the first crt.sh sweep **silently failed for `welt.de`
> (0 names harvested)** — crt.sh returned 502s and the harness kept going. `welt.de` is a Tier 1 brand.
> Always verify per-domain counts, not just the total. Fixed by `enum-crt-pass2.sh` (retries + failure
> detection).
>
> **Methodology lesson from phase 13:** CT enumeration **never found `api.politico.eu`** — a Tier 1
> production Rails API. It surfaced only by **following a redirect chain** from `help.politico.eu`.
> Always read `Location` headers and walk redirects; DNS/CT enumeration alone will miss hosts.
>
> **Same lesson, phase 15:** `login.prod.ps.bild.de` and **`whoami-api.prod.ps.bild.de`** (the JWT
> trust service) were also invisible to CT — found only by diffing **anonymous vs authenticated**
> responses. Authenticated diffing surfaces hidden backend hosts.

---

## 3. Findings

### 3.1 CANDIDATE — internet-exposed unpatched ADSelfService Plus  `finding-adssp-dev1.md`

**Asset:** `dev1–5.epaper.welt.de` (Tier 2, `*.welt.de`) · all five resolve to `asse-dev.004dev.com`
**Product:** ManageEngine ADSelfService Plus **build 6519** — an identity/credential-management system
(password resets, MFA enrolment), branded "004 GmbH – Account Self Service", **internet-facing despite a
`dev` hostname**.

Vulnerable to four known HIGH CVEs per the vendor's own advisory page:

| CVE | Affected | Fixed | Nature |
| --- | --- | --- | --- |
| CVE-2026-3183 | ≤6523 | 6524 | **MFA bypass** with a valid user password |
| CVE-2026-1367 | ≤6522 | 6523 | SQL injection (authenticated technician) |
| CVE-2026-2740 | ≤6524 | 6525 | Authenticated RCE (remote agent install) |
| CVE-2026-11374 | ≤6528 | 6529 | Predictable SSO tickets (**unauthenticated**) — AD360 only |

**Evidence:** version from static asset query strings, `?build=6519`, identical on all five hosts, stable
across refetches. Product confirmed via `JSESSIONIDADSSP`, Zoho `zsec` libs, and the
`{"eSTATUS":"adssp.security.exception.pattern_not_matched"}` error namespace.

**Honest limitations:**
- **Version-based only. No exploitation performed.** RoE: *"submissions without proof of concept will not be
  considered"* → may be triaged informational.
- Three of four require authentication; none is unauthenticated RCE. **No unauthenticated detection script is
  possible for them** — the vulnerable path is post-login. The only unauthenticated CVE (11374) needs AD360
  integration and is a ticket-prediction attack, not a scripted check.
- The famous ADSSP public exploit paths (**CVE-2021-40539** auth-bypass→RCE, **CVE-2022-47966** pre-auth SAML
  RCE) are **patched** at 6519 (fixes were ~6113).
- Third-party hosting: 004 GmbH's product on a `*.welt.de` name. In scope by wildcard, remediation is theirs.

**To upgrade to High:** obtain a low-privilege test account for the portal → CVE-2026-3183 becomes directly
testable.

#### Secondary observation — NOT a finding
`POST /UnAuthAction.cc` with `methodToCall=populateEmpSearch` is reachable unauthenticated (200) and drives
the login-page employee-search widget. `methodToCall` is a **Struts2 DMI** primitive, but a **method-name
allowlist correctly blocks** dangerous values (`show`, `serverSettings` → 400 `pattern_not_matched`; case,
whitespace and null-byte variations all rejected). Feature is disabled on this instance (empty response).

> ⚠️ **Unresolved, do not retest without authorisation:** Struts2 **bang-DMI** path syntax
> (`UnAuthAction!serverSettings.cc`, `UnAuthAction.cc!serverSettings`) **wedged the connection twice**,
> surviving both `curl -m 12` and `timeout 15`. Potentially a DoS primitive. I stopped rather than hammer a
> live worker. Host was healthy afterwards (200 in 0.21 s). Confirming this is a **destructive** test.

### 3.2 BACK POCKET — credentialed CORS wildcard  `recon-findings.md` §6 P1

`Access-Control-Allow-Origin` reflects **any subdomain** of `bild.de`, `welt.de`, `autobild.de`,
`computerbild.de`, `sportbild.de`, `spring-media.de`, `axelspringer.de`, with
**`Access-Control-Allow-Credentials: true`** — on `consumer-api.prod.auth.bild.de` (sessions/identity) and
`checkout-next-api.prod.ps.bild.de` (purchases/payment prep; also accepts arbitrary ports).

Bad origins *are* correctly rejected (naive reflect, `null`, lookalikes). The weakness is wildcard depth.
Exploit requires a foothold (**XSS / subdomain takeover / SSRF**) on one of those seven domains. **I hunted
and found none** — all CloudFront/Shopify/zeroheight/Webflow candidates are live and claimed.

Kept because it **amplifies** any future bug: an XSS or SSRF anywhere on those domains turns into
credentialed read access to the auth and commerce APIs. Allowlisted watch-list: `*.spring-media.de`,
`*.axelspringer.de`. Note `*.springtools.de` is **not** allowlisted.

### 3.3 Everything else — tested and clean (the bulk of the work)

- **Auth perimeter** — whoami/sessions 401 unauth; `/sessions/{id}` DELETE-only and fails safe
  (204 on others' IDs **without deleting**); settings flow bound to caller; `identity_id` param ignored;
  `returnTo` allowlisted (no open redirect); CSRF enforced on `fed-cm`; JWT rejects `alg:none` and
  `HS256` forgery; **prod sessions rejected by UAT** (env isolated).
- **Cache poisoning** (the RoE-invited one) — **not present.** Unique cache-busters throughout; no unkeyed
  header reflection (`X-Forwarded-Host`, `X-Host`, `X-Original-URL`, …); cache key correctly includes
  **Origin *and* query string**; Ory API is `cf-cache-status: DYNAMIC` + `no-store`. Auth/anon HTML is
  byte-identical, so nothing per-user to poison.
- **Cross-brand Ory sharing** — bild.de, welt.de and computerbild.de share **one Ory project**
  (`recursing-archimedes-wer2643ri7`); a bild session authenticates on computerbild; identical JWKS. All
  UAT/stage share a second project. Likely **intentional unified AS SSO** (`subOrigin:"as"`). **Open
  question: do entitlements leak cross-brand?** Untestable without a paid account.
- **Hey chat** — all 640 `experienceId` values are **UUIDv4**, not guessable. Directly answers the
  RoE's invitation (negative). `paidOnly` teaser is by design (402 gates interaction).
- **`*.asadcdn.com` (Tier 1)** — open Prebid Server, but `/info/bidders*` is documented public metadata
  (no keys/accounts), and every SSRF-prone adapter is **DISABLED** (`adkernel`, `adkernelAdn`,
  `adtelligent`, `generic`, `colossus`); the 22 active bidders have fixed endpoints.
- **`adtechnology.axelspringer.com` (Tier 1)** — clean.
- **Tier 1 apexes** — `epaper.welt.de`, `cancellation.prod.ps.welt.de`, `digital.welt.de`, `go.welt.de`,
  `meinkonto.bild.de`: S3/CloudFront SPA catch-alls. **Caution:** they return 200 for *every* path
  (incl. `/api`, `/admin`, `/.git/HEAD`) — that's a catch-all, not exposure.
- **S3** — `ps-kitchen-prod-assets` correctly 403 (no listing).
- **Devel/stage** — `digasred[.stage].computerbild.de` (403 Akamai), `vc.stg.vip-club.computerbild.de`
  (403), `edition-issues-devel.ep.welt.de` (S3, no index). Locked down.

### 3.4 Considered and REJECTED — tested and correctly controlled

Recorded so they are not re-filed or re-tested. Where marked **tested**, the control was verified
directly rather than assumed.

| Item | Outcome |
| --- | --- |
| `DELETE /sessions/{id}` → 204 without deleting | RoE line 705: *"Sessions not being invalidated"* — the named exclusion. |
| Email not verified before session issued | No exploit scenario → severity "None" (RoE 669–670). |
| OIDC issuer mismatch (UAT declares stage issuer) | Spec violation, no demonstrated RP impact → "None". **Also explained**: bild UAT and stage are the *same Ory project*. |
| PKCE `plain` enabled in prod | Exploit scenario is MITM (excluded, RoE 676–677); adjacent to OAuth exclusions (699). |
| `data-*.welt.de` + Tier 3 `/metrics` | 114 bytes of queue stats. No PII/credentials. Informational. |
| `dev1–5` malformed `SameSite = None` cookies | Malformed → ignored → falls back to **Lax (more** restrictive). Functional bug, not security. |
| **`returnTo` / `redirect_url` / `redirect_uri`** | **TESTED** across all brands and envs. Foreign hosts → 400. No open redirect. |
| **`newsos.com` DCR** | **TESTED.** Open registration + **6 allowlist-bypass patterns** — all rejected. Validator parses origin correctly (rejects `example.invalid@newsos.com`). Zero clients created. §3m |
| **`suche.fitbook.de` search** | **TESTED.** Context-aware JS+HTML encoding (no reflected XSS), no SSRF, no pagination abuse. Only a missing rate limit → Informational. |
| **`pur.*` contentpass OIDC** | **TESTED.** Arbitrary `propertyId` rejected; `redirect_uri` strictly validated. |
| **`*.asadcdn.com` Prebid Server** | **TESTED.** All SSRF-prone adapters DISABLED; `/info/bidders` is documented public metadata. |
| **`api.politico.eu`** | Version disclosure + 500 on missing param → Informational. |

> **Pattern worth recording:** six separate things *looked* exploitable at first glance —
> open-redirect-shaped `returnTo`, a 71 KB bidder dump, credentialed CORS wildcard, all-paths-200
> SPAs, an unauthenticated DCR endpoint, and a search page. Each was investigated and each is
> controlled. **This target is well-defended**; treat that as the finding, not a gap in the work.

---

## 4. Outcomes & open items (engagement closed)

### 4.1 Final disposition

| Item | Disposition |
| --- | --- |
| **ADSSP build 6519** (`dev1–5.epaper.welt.de`) | **Candidate finding**, documented in `finding-adssp-dev1.md`. Version-only evidence — no PoC, not filed, no programme contact. |
| **Credentialed CORS wildcard** | Back-pocket amplifier only (§3.2). Not reportable alone — no foothold found. |
| Everything else | **Tested and clean**, or RoE-excluded (§3.3, §3.4). |

**No submission was filed.** Engagement closed by decision, not by finding.

### 4.2 Deliberately NOT pursued (constraints at sign-off)

- **Programme contact / test-account request** — user chose not to. ADSSP therefore stays version-only
  rather than being escalated to a High-severity MFA-bypass PoC.
- **Cross-brand entitlement test** — needs a **paid** BILDplus/WELTplus/CoBi subscription. This is the
  **one substantive question left open** and the highest-value item if the engagement is ever resumed
  (see §3i: all three prod brands share one Ory project).
- **ADSSP bang-DMI hang** (`UnAuthAction!serverSettings.cc`) — wedged the connection twice. Confirming it
  is a **destructive availability test** requiring authorisation. Not attempted further.
- **newsos DCR** — fully tested and **closed as not vulnerable** (§3m), including six allowlist-bypass
  patterns. Not an open item.

### 4.3 Surface not covered (for completeness)

- `pss.welt.de` — new domain (`prod` + `uat`, `pss-deli.*`); only roots probed. UAT mirrors prod, no
  API/debug paths found. **Low expectations.**
- Deep path fuzzing of any host — out of scope per the RoE's "no intrusive commands in production".

### 4.4 Explicitly out of scope — do NOT file
Confirmed against the RoE's own clauses (full detail in §3.4): `DELETE /sessions/{id}` returning 204;
unverified email at signup; OIDC issuer mismatch; PKCE `plain`; `data-*` `/metrics` disclosure;
`suche.fitbook.de` missing rate limit; `api.politico.eu` version disclosure and 500. **All are either
named exclusions or carry no realistic exploit scenario → severity "None".**

### 4.5 If this engagement is ever resumed
1. Test **cross-brand entitlements** with a paid account (§3i) — the only high-value question left.
2. Re-check the **CORS chain** (§3.2) if any XSS/takeover appears on the seven allowlisted domains.
3. `pss.welt.de` path coverage.
4. If the programme will accept patch-lag: file the **ADSSP** finding and notify vendor **004 GmbH**.

---

## 5. File map

### Documents
| File | Contents |
| --- | --- |
| `README.md` | This handoff document |
| `scope.md` | Full RoE extraction (tiers, exclusions, bounties, worst cases) |
| `recon-findings.md` | **Main findings doc** — §1–3j. Cache, CORS, auth, Hey, adtech, Tier 1, cross-brand, **§6 back-pocket** |
| `finding-adssp-dev1.md` | **Draft report** for the ADSSP candidate finding |
| `probe-summary.md` | Initial probe summary (phase 2–5) |

### Data
| File | Contents |
| --- | --- |
| `targets.txt` / `ip-ranges.txt` | 39 apex assets / 12 in-scope IPs |
| `dns-resolved.tsv` | A + CNAME per apex asset |
| `http-probe.tsv` / `http-final.tsv` | Apex HTTP probes (raw / redirect-followed) |
| `crt-subdomains.txt` | Pass-1 CT names (4,467) — **`welt.de` missing, see §2** |
| `crt-all.txt` | **Combined corpus, 5,002 names** — use this one |
| `resolved.tsv` | Resolving subdomains |
| `subdomains-http.tsv` / `subdomains-http2.tsv` | Probed endpoints (pass 1 / pass 2) |
| `live-endpoints.tsv` / `live-hosts.txt` | **336 live endpoints** (sinkholes excluded) |
| `targets-priority.tsv` | 58 auth/admin/checkout/api/staging candidates |
| `recon/evidence/*.json` | OIDC discovery documents (issuer evidence) |
| `recon/legacy/adv-CVE-*.html` | **ManageEngine advisory pages** (the CVE evidence) |
| `recon/findings/metrics-welt.json` | The `/metrics` payload |
| `recon/hey/experiences.json` | 640 Hey experiences (UUIDv4 evidence) |
| `recon/newsos/registration-attempt.log` | **DCR verification transcript** (§3m) |
| `recon/newsos/bypass-attempts.log` | **6 allowlist-bypass attempts** — all rejected (§3m) |
| `recon/legacy/adv-CVE-*.html` | 30 ManageEngine advisory pages (CVE evidence) |
| `recon/authdiff/all-diffs.tsv` | Anon-vs-authenticated diff results (§3l) |
| `recon/crt-pass2.txt` | Pass-2 CT names (recovers `welt.de` etc.) |
| `recon/ps-hosts.txt` | `ps.*` host inventory incl. out-of-scope estate |

### Scripts (reproducible)
| File | Purpose |
| --- | --- |
| `probe-http.sh` | Apex DNS+HTTP liveness |
| `enum-crt.sh` / `enum-crt-pass2.sh` | CT enumeration (pass 2 has retries + failure detection) |
| `probe-subdomains.sh` | Parallel HTTP probe of resolved hosts |
| `authtest.sh` | Authenticated access-control harness (needs `creds/`) |

### `creds/` — **gitignored, never commit**
`creds/account-a.cookie`, `creds/account-b.cookie` (test sessions). Verified: no cookie values appear in any
tracked file.

---

## 6. Housekeeping ⚠️ (outstanding before reuse)

Nothing was filed, so none of this blocks a submission — but do it before reusing the artefacts.

1. **Rotate the two test sessions.** Both accounts' full session cookies were pasted into the working chat on
   2026-09-26. Log out both accounts (or change passwords) to invalidate. Verified: `creds/` is gitignored and
   **no session value appears in any tracked file** — only the cookie *name* (`ory_session_…`), which is the
   Ory project slug and already public in DNS CNAMEs.
2. **Clear the unintended purchase intent** — `POST /api/prepare-purchase` returned 200 and created
   `purchaseId 3JqMPu3Q84QwfgNjZnlfZZSgsDw` on production under account A, while probing validation. No payment
   taken, no entitlement granted, but it is a state write that was not intended. Disclose it if ever filed.
3. **No writes were made to the ADSSP host** — all testing there was read-only fingerprinting.
4. **No OAuth client was created at `newsos.com`** — all seven registration attempts returned `400` (rejection),
   so the production authorization server holds **no stray client**. Verified by response codes in
   `recon/newsos/*.log`.
5. **Session-cookie hygiene during testing:** the session cookie was sent **only** to first-party AS domains
   (456 of 573 hosts) and **never** to third-party vendor hosts (TollBit, Emarsys, Flowmailer, Sourcepoint,
   wetterkontor), so no credentials were disclosed to vendors.

---

## 7. Reproduction

```bash
cd bug-bounties/intigriti/axelspringerse

# 1. scope + apex liveness
./probe-http.sh                                   # -> http-final.tsv

# 2. subdomain enumeration (pass 2 is the reliable one)
./enum-crt-pass2.sh                               # -> recon/crt-pass2.txt
cat crt-subdomains.txt recon/crt-pass2.txt | sort -u > crt-all.txt

# 3. resolve + probe
#    (see §2 phases 5/8 for the exact pipelines)
./probe-subdomains.sh resolved.tsv probe.tsv       # -> live endpoints

# 4. authenticated tests (needs creds/account-{a,b}.cookie)
./authtest.sh                                      # read-only by default
CONFIRM_DELETE=1 ./authtest.sh                     # adds the destructive probe — deliberate only
```

**ADSSP fingerprint (single safe request):**
```bash
curl -sk https://dev1.epaper.welt.de/showLogin.cc | grep -oE 'build=[0-9]+'
# -> build=6519
```

---

## 8. Principles applied

- **RoE first.** Every candidate was checked against the exclusion list before being called a finding.
  Multiple items that *looked* like findings were rejected on scope grounds (§3.4) — the correct outcome,
  not a shortfall.
- **No intrusive commands in production.** No fuzzing, no brute force, no DoS. Auction requests were never
  submitted; the ADSSP DMI hang was **not retested**; no credential attacks were attempted (§RoE).
- **Cache testing never touched a live URL** — a unique cache-buster on every probe.
- **Credential hygiene.** The test session cookie was never sent to third-party vendor hosts.
- **Minimal-footprint testing.** The two state-changing tests were each **one deliberate request**, chosen so
  they could only return a rejection or a control: the inert `newsos` registration (`.invalid` redirect URI,
  guaranteed un-abusable) and the six bypass patterns. Both were logged verbatim, and testing **stopped on
  any success** to avoid leaving artefacts. **Zero artefacts were created.**
- **Distinguished verification from provisioning.** Testing a *bypass pattern* can reveal a real bug, so it
  is worth doing. Testing an *allowlisted* value can only produce a useless artefact, so it was declined —
  and enumerating the allowlist was declined for the same reason.
- **Negative results documented with the same rigour as positives** — including *how* each control was ruled
  out, so the work is reproducible and not merely asserted.
- **No exploitation of the ADSSP CVEs.** Version correlation only; no auth attempts, no MFA bypass.
```
(\_/)
(o.o)
(> <) rabbit-hole-research
```
