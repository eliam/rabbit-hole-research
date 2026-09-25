# RECON.md — Port of Antwerp-Bruges (Intigriti)

**Researcher:** eliam
**Date:** 2026-09-25 08:59 
**Program:** Port of Antwerp-Bruges (Intigriti, open, Tier 2/Tier 3)
**Rules of engagement applied:** all requests sent from an `@intigriti.me`-registered
identity; automated tooling capped at **max 5 req/s** (the probe used 4 req/s).
RoE table: `@intigriti.me` = **Required** (email/alias); *User agent* = Not applicable;
*Automated tooling* = max 5 requests/sec; *Request header* = Not applicable.
A normal browser User-Agent is therefore fine — an earlier note in this project
over-stated a UA requirement; the mandatory element is the **`@intigriti.me`
address**, not the `User-Agent` header.
~300 target-directed requests in total across all probes (DNS and the crt.sh
lookup excluded — crt.sh was returning 502).

---

## 1. Scope

From `intigriti.portofantwerp.scope` (scraped asset table). 59 asset rows total:
54 URL, 2 IP Range, 2 Wildcard, 1 Mobile (the Mobile row has an empty value in
the scrape and is unusable).

| Tier | Assets |
|---|---|
| Tier 2 (bounty) | 2 IP ranges + 42 URLs |
| Tier 3 (bounty) | `erpx.unit4cloud.com/u4erx_pab_acp1`, `/u4erx_pab_prev`, `/u4erx_pab_prod` |
| **No bounty** | `*.portofantwerp.com`, `*.portofantwerpbruges.com` |
| **Out of scope** | `jobs.*` (both), `media.*` (both), `future.*` (both), `register.*` (both), `www.oursustainableport.com` |

### Scope traps

1. **The wildcards pay nothing.** `*.portofantwerp.com` and
   `*.portofantwerpbruges.com` are listed as **"No bounty"**. Any subdomain not
   explicitly enumerated as a `URL` asset is testable but yields **€0**.
2. **`register.*` is out of scope, but `register-accpt.*` is Tier 2.** Same for
   `media-*`/`jobs-*` (out) vs `my-*`/`wiki-*` (in). Easy to confuse when you
   are four hours deep.
3. **`maximo.portofantwerpbruges.com` is listed twice** in the scope file.
4. Bounty-paying URLs extracted to `targets-web.txt` — 45 lines, **44 unique**
   (42 Tier 2 + 3 Tier 3; `maximo.portofantwerpbruges.com` is listed twice, see
   trap 3). Of the 54 URL assets, 9 are out of scope and the 2 wildcards pay
   nothing.
5. `erpx.unit4cloud.com` is **third-party SaaS** (Unit4). It is a listed asset,
   but it is not POA infrastructure — testing the vendor platform can breach
   Unit4's own terms even though POA lists it. Treat with care / prefer the
   POA-owned apps.

### Three families per application

Every app exists in a `portofantwerp.com` and a `portofantwerpbruges.com` flavour,
plus `-accpt` (acceptance) and sometimes `-test` variants. The
`portofantwerp.com` aliases are almost all **pure redirectors** to the
`.portofantwerpbruges.com` canonical host:

```
apps.portofantwerp.com     -> https://apps.portofantwerpbruges.com/
my.portofantwerp.com       -> https://my.portofantwerpbruges.com/
webapps.portofantwerp.com  -> https://webapps.portofantwerpbruges.com/
wiki.portofantwerp.com     -> https://wiki.portofantwerpbruges.com/
```

This is a good default-config signal (HSTS `includeSubdomains; preload` present)
but it also means there is little to test on the `.com` side itself.

---

## 2. IP range recon (Tier 2) — negative result

Both ranges were masscan'd (TCP, ~200 ports incl. 3389/5985/2375/6379/9200/8443/10443)
and then service-detected with nmap. Ranges: `94.107.237.192/26`, `188.118.8.0/25`
(192 hosts).

**8 hosts up, 4 ports, nothing exploitable:**

| Host | Port | Service | Assessment |
|---|---|---|---|
| `94.107.237.201` | 179/tcp | BGP, `tcpwrapped` | Router, zero response |
| `188.118.8.121` | 179/tcp | BGP, `tcpwrapped` | Router, zero response |
| `188.118.8.118` | 4500/tcp | IKE NAT-T | IPsec concentrator |
| `94.107.237.205` | 443/tcp | MS-HTTPAPI/2.0 | SSTP/AoVPN |
| `188.118.8.9` | 443/tcp | MS-HTTPAPI/2.0 | SSTP/AoVPN |
| `188.118.8.10` | 443/tcp | MS-HTTPAPI/2.0 | SSTP/AoVPN |
| `94.107.237.228` | 80/tcp | `Server: BigIP` | F5 VIP, bare 302 |
| `188.118.8.52` | 80/tcp | `Server: BigIP` | F5 VIP, bare 302 |

### The three SSTP/AoVPN endpoints all share one certificate

```
subject = CN=aovpn.portofantwerpbruges.com
issuer  = DC=local, DC=antwerpen, DC=haven, CN=POA Root CA 2
valid   = 2023-03-28 .. 2031-03-26
EKU     = TLS Server Auth, IP security IKE intermediate (1.3.6.1.5.5.8.2.2), TLS Client Auth
```

No SAN extension. `1.3.6.1.5.5.8.2.2` is the IKE-intermediate OID, so these
certificates are for **IPsec/IKE machine authentication** — i.e. certificate-based
Always-On-VPN, not PSK. That closes the classic IKE aggressive-mode PSK-cracking
path.

### Origin hypothesis — tested and disproven

Because every web asset sits behind Cloudflare while the F5 `PoABLB*` cookies
prove an F5 BIG-IP sits at the origin, the obvious hypothesis was that the
in-scope `/26` and `/25` ***are*** those origins, reachable with a `Host:` header
(WAF bypass / direct-origin access).

**Probe B tested this directly: 45 scope hostnames × 5 in-scope web IPs. Result:
zero real differentiation.** Both port-80 VIPs return the identical
`302 -> https://<ip>/` (`Server: BigIP`) for every `Host:` value — a catch-all
default pool with no vhost routing. The three port-443 hosts likewise returned the
identical `404` MS-HTTPAPI response for every valid hostname.

> Artifact caveat: Probe B reported 4 "DIFF" rows per 443 host, but those are
> **false positives from this script** — the entries were
> `webapps-test.portofantwerpbruges.com/xui` and the three `erpx.unit4cloud.com/...`
> assets, whose embedded `/` path made the `Host:` header malformed and produced a
> `400 Bad Request`. Not a finding.

**Conclusion: the Tier-2 IP ranges do not serve any scope hostname. Do not spend
further time on them.** They are network infrastructure (BGP, VPN, LB) with no
application surface. UDP 500/4500 were never scanned and remain the only
untested angle — an IKE finding at best, and IKE fuzzing against a live VPN
carries DoS risk.

---

## 3. Web asset probe — results

34 of 44 unique targets answered; 10 have no public DNS record at all.
(`targets-web.txt` holds 45 lines — `maximo.portofantwerpbruges.com` is
duplicated in the scope file, so 44 unique hosts were probed.)

| Host | Sch | Code | Server | Location | Tech |
|---|---|---|---|---|---|
| `api-accpt.portofantwerpbruges.com` | https | 200 | cloudflare | `` | Cloudflare |
| `api.portofantwerpbruges.com` | https | 200 | cloudflare | `` | Cloudflare |
| `apps-accpt.portofantwerpbruges.com` | https | 301 | cloudflare | `https://my-accpt.portofantwerpbruges.com/profile/` | F5-LTM Cloudflare |
| `apps.portofantwerp.com` | https | 302 | cloudflare | `https://apps.portofantwerpbruges.com/` | Cloudflare |
| `apps.portofantwerpbruges.com` | https | 301 | cloudflare | `https://my.portofantwerpbruges.com/profile/` | F5-LTM Cloudflare |
| `digitalspecs.portofantwerpbruges.com` | https | 200 | cloudflare | `` | F5-LTM Cloudflare |
| `erpx.unit4cloud.com/u4erx_pab_acp1` | https | 200 | - | `` | Unit4-ERP |
| `erpx.unit4cloud.com/u4erx_pab_prev` | https | 200 | - | `` | Unit4-ERP |
| `erpx.unit4cloud.com/u4erx_pab_prod` | https | 200 | - | `` | Unit4-ERP |
| `login-accpt.portofantwerpbruges.com` | https | 302 | cloudflare | `https://my-accpt.portofantwerpbruges.com/profile/` | Cloudflare |
| `login-test.portofantwerpbruges.com` | https | 302 | cloudflare | `https://my-test.portofantwerpbruges.com/profile/` | Cloudflare |
| `maximo.portofantwerp.com` | https | 302 | cloudflare | `https://maximo.portofantwerpbruges.com/` | Cloudflare Maximo |
| `maximo.portofantwerpbruges.com` | https | 302 | cloudflare | `https://maximo.manage.mas.portofantwerpbruges.com/maximo` | Cloudflare Maximo |
| `my-accpt.portofantwerp.com` | https | 302 | cloudflare | `https://my-accpt.portofantwerpbruges.com/` | Cloudflare |
| `my-accpt.portofantwerpbruges.com` | https | 301 | cloudflare | `http://my-accpt.portofantwerpbruges.com/profile/` | F5-LTM Cloudflare |
| `my.portofantwerp.com` | https | 302 | cloudflare | `https://my.portofantwerpbruges.com/` | Cloudflare |
| `my.portofantwerpbruges.com` | https | 301 | cloudflare | `http://my.portofantwerpbruges.com/profile/` | F5-LTM Cloudflare |
| `notula-accpt.portofantwerpbruges.com` | https | 200 | nginx/1.27.1 | `` | nginx |
| `register-accpt.portofantwerp.com` | https | 302 | cloudflare | `https://register-accpt.portofantwerpbruges.com/` | Cloudflare |
| `register-accpt.portofantwerpbruges.com` | https | 301 | cloudflare | `http://register-accpt.portofantwerpbruges.com/account/` | F5-LTM Cloudflare |
| `servicedesk-accpt.portofantwerp.com` | https | 302 | cloudflare | `https://servicedesk-accpt.portofantwerpbruges.com/` | Cloudflare |
| `servicedesk-accpt.portofantwerpbruges.com` | https | 302 | cloudflare | `/plugins/servlet/samlsso?redirectTo=%2F` | Cloudflare Jira-SM |
| `servicedesk.portofantwerp.com` | https | 302 | cloudflare | `https://servicedesk.portofantwerpbruges.com/` | Cloudflare |
| `servicedesk.portofantwerpbruges.com` | https | 302 | cloudflare | `/plugins/servlet/samlsso?redirectTo=%2F` | Cloudflare Jira-SM |
| `webapps-accpt.portofantwerp.com` | https | 302 | cloudflare | `https://webapps-accpt.portofantwerpbruges.com/` | Cloudflare |
| `webapps-accpt.portofantwerpbruges.com` | https | 301 | cloudflare | `https://my-accpt.portofantwerpbruges.com/profile/` | F5-LTM Cloudflare |
| `webapps-test.portofantwerpbruges.com/xui` | https | 200 | cloudflare | `` | Cloudflare JWT-app |
| `webapps.portofantwerp.com` | https | 302 | cloudflare | `https://webapps.portofantwerpbruges.com/` | Cloudflare |
| `webapps.portofantwerpbruges.com` | https | 301 | cloudflare | `https://my.portofantwerpbruges.com/profile/` | F5-LTM Cloudflare |
| `wiki-accpt.portofantwerp.com` | https | 302 | cloudflare | `https://wiki-accpt.portofantwerpbruges.com/` | Cloudflare |
| `wiki-accpt.portofantwerpbruges.com` | https | 301 | cloudflare | `http://wiki-accpt.portofantwerpbruges.com/confluence/` | F5-LTM Cloudflare Confluence |
| `wiki.portofantwerp.com` | https | 302 | cloudflare | `https://wiki.portofantwerpbruges.com/` | Cloudflare |
| `wiki.portofantwerpbruges.com` | https | 301 | cloudflare | `http://wiki.portofantwerpbruges.com/confluence/` | F5-LTM Cloudflare Confluence |
| `www.portofantwerpbruges.com` | https | 307 | cloudflare | `/en` | Cloudflare Next.js |
| `api-accpt.portofantwerp.com` | - | - | - | `-` | no DNS / no AAAA-A response |
| `api.portofantwerp.com` | - | - | - | `-` | no DNS / no AAAA-A response |
| `apps-accpt.portofantwerp.com` | - | - | - | `-` | no DNS / no AAAA-A response |
| `maximo-accpt.portofantwerp.com` | - | - | - | `-` | no DNS / no AAAA-A response |
| `maximo-accpt.portofantwerpbruges.com` | - | - | - | `-` | no DNS / no AAAA-A response |
| `oprc.portofantwerpbruges.com` | - | - | - | `-` | no DNS / no AAAA-A response |
| `share-accpt.portofantwerp.com` | - | - | - | `-` | no DNS / no AAAA-A response |
| `share-accpt.portofantwerpbruges.com` | - | - | - | `-` | no DNS / no AAAA-A response |
| `share.portofantwerp.com` | - | - | - | `-` | no DNS / no AAAA-A response |
| `share.portofantwerpbruges.com` | - | - | - | `-` | no DNS / no AAAA-A response |

### Reading the table

- **`Server: cloudflare` + `cf-ray`** on 32 of 34 — all application testing
  is mediated by Cloudflare. Origin is shielded.
- **`PoABLBprod` / `PoABLBaccpt`** cookies on every app = **F5 BIG-IP LTM**,
  with the ACCPT/PROD pool baked into the cookie name. **`TS01d85b23` /
  `TS014487d3`** = F5 BIG-IP ASM (bot defence). Stack is therefore:
  `Cloudflare -> F5 BIG-IP ASM/LTM -> origin`. Every hop is a WAAP.
- **`BIGipServer<random>`** cookie values differ per app, confirming separate
  pools per vhost.
- The 10 unreachable hosts are the **employee-facing / internal-only apps**:
  `share.*` (4), `maximo-accpt.*` (2), `api.portofantwerp.com`,
  `api-accpt.portofantwerp.com`, `apps-accpt.portofantwerp.com`,
  `oprc.portofantwerpbruges.com`. They have no public A record at all — they are
  only reachable from inside the VPN. This is precisely why the IP ranges are in
  scope, and precisely why they are a dead end from the outside.
- `oprc.portofantwerpbruges.com` **publicly resolves to `172.27.234.6`** — an
  RFC1918 address in public DNS. This is a (very low severity) internal-topology
  disclosure; it confirms an internal `172.27.0.0/16` range.
- `notula-accpt.portofantwerpbruges.com` resolves to `193.190.121.207` (Belnet)
  and is **not** behind Cloudflare.
- `erpx.unit4cloud.com` -> `150.171.109.215` (Unit4/Microsoft SaaS).
- `www.portofantwerpbruges.com` is a **Next.js** app (`NEXT_LOCALE` cookie,
  `307 -> /en`).

---

## 4. Findings

Nothing confirmed yet — these are ranked leads with the evidence that produced
them. Severity is my provisional call before exploitation.

### F-1 · `notula-accpt` is an unproxied origin (lead, high interest)

`notula-accpt.portofantwerpbruges.com` (`193.190.121.207`) answers
`200` with `Server: nginx/1.27.1`, title **"Green Valley Suite"**, and **no
Cloudflare / no F5 cookies**. It is the only Tier-2 asset in the entire scope
that is not behind the WAAP stack.

Value: it is the one target where findings are directly exploitable without
Cloudflare/F5 filtering you on payload shape. It is a third-party product
("Green Valley Suite") — confirm the vendor and check for known CVEs before
manual testing. Note nginx 1.27.1 is recent (mainline, Sep 2024), so nginx itself
is not the angle; the application is.

### F-2 · Hostnames outside the declared scope list (informational)

Live redirects disclosed hostnames that are **not** among the 54 listed URLs:

| Discovered | Source | Status |
|---|---|---|
| `login.portofantwerpbruges.com` | SSO redirect from `my.*` / `wiki.*` | Wildcard only → **no bounty** |
| `my-test.portofantwerpbruges.com` | `302` from `login-test.*` | Wildcard only → **no bounty** |
| `maximo.manage.mas.portofantwerpbruges.com` | `302` from `maximo.*` | Wildcard only → **no bounty** |
| `server`/`profile`/`account` paths | F5/ASM cookies | n/a |

This is a concrete scope-management trap: `login-test.*` **is** Tier 2, and it
hands you `my-test.*`, which is **not**. Test the Tier-2 host, not its redirect
destination, if you want to be paid.

### F-3 · Central SSO redirect parameters (candidate, untested)

Every app bounces unauthenticated users to:

```
https://login.portofantwerpbruges.com/poam/?service=GlobalAuthenticationPolicyLevel25_poab
  &goto=https%3A%2F%2Fmy.portofantwerpbruges.com%3A443%2Fagent%2Fcustom-login-response%3Fstate%3DE8zi...%26service%3D...
  &original_request_url=https%3A%2F%2Fmy.portofantwerpbruges.com%3A443%2Fprofile%2F
```

Three attacker-controllable-looking parameters (`goto`, `original_request_url`,
`service`) in a single auth flow. `agent/custom-login-response` + `state` is the
classic **CA/Broadcom SiteMinder** Web Agent pattern — i.e. an identity product,
not a bespoke app.

Hypotheses to test, in order: open redirect via `original_request_url` /
`goto` (post-auth redirect is the highest-value redirect because it usually
carries a session), then parameter tampering on `service` to pivot the SAML
audience, then `state` predictability. Tier-wise this lives on `login.*`
(wildcard, no bounty) but it is reached *from* Tier-2 hosts, so check whether the
finding can be framed against the Tier-2 entry point.

### F-4 · Jira Service Management `redirectTo` (candidate, untested)

`servicedesk.portofantwerpbruges.com` and `servicedesk-accpt.*` are **Jira
Service Management** — both return
`302 /plugins/servlet/samlsso?redirectTo=%2F` with a `JSESSIONID`. The
`redirectTo` parameter on the SAML servlet is the standard Jira open-redirect /
SSRF probe surface. Both prod and ACCPT are in scope at Tier 2; do ACCPT first.

### F-5 · Confluence instances (lead)

`wiki.portofantwerpbruges.com` and `wiki-accpt.portofantwerpbruges.com` redirect
to `/confluence/`. Confluence has a long CVE history
(CVE-2023-22515/22518, CVE-2022-26134, CVE-2021-26084). Version identification is
the prerequisite and is *not* yet done — this is the single highest expected-value
check on the board if the version is old or reachable unauthenticated. Do not
launch an exploit without confirming version; Confluence exploits are
destructive to the target.

### F-6 · `webapps-test.../xui` with a JWT cookie (lead)

`webapps-test.portofantwerpbruges.com/xui` returns `200` and sets an
**`am-auth-jwt`** cookie. The scope grants that specific `/xui` path. A client-side
JWT in a cookie makes this a JWT-handling target (alg confusion, expiry,
audience, signature verification). Note the app sets the cookie *before*
authentication, so the JWT is likely an anonymous/session bootstrap token —
decode it first.

### F-7 · Considered and rejected

- **HTTPS→HTTP redirect downgrade.** `my.*`, `wiki.*`, `register-accpt.*` and
  others return `301 Location: http://<host>/...` **from an https request**. This
  looked like a reportable redirect-downgrade, but every host also sends
  `strict-transport-security: max-age=16070400; includeSubdomains; preload`.
  HSTS neutralises it. **Not a finding — do not report.**
- **`TS*` cookies without `Secure`/`HttpOnly`** on `TS01d85b23`
  (`Path=/` only). F5 ASM bot-defence cookies carrying no session value; not a
  vulnerability.
- **BGP / IKE / SSTP endpoints.** No application surface, certificate-based auth,
  and no pre-auth reachable service. Out of interest for this engagement.

---

## 5. Recommended TTPs / next actions

Ranked by expected value per unit of risk. Respect `User-Agent: eliam@intigriti.me`
and **≤5 req/s** on everything below.

1. **`notula-accpt` (F-1) — go direct.** No CDN in front, so this is where
   results are cheapest. Fingerprint the app first (`/`, `/api`, favicon hash,
   JS bundle), identify "Green Valley Suite" and its vendor, then diff against
   known CVEs. Identify the product before sending payloads.
2. **Confluence version check (F-5).** Unauthenticated version disclosure on
   `wiki-accpt.*` is a `GET` or two (`/confluence/login.action`,
   `/confluence/rest/api/...`, `/confluence/about`). Only escalate if the version
   is known-vulnerable **and** unauthenticated RCE is in play. ACCPT first.
3. **Auth-flow parameter tampering (F-3).** Enumerate `goto` /
   `original_request_url` / `service` on `login.*`, ACCPT and PROD. Redirect
   handling usually differs between the two. Low request count, high payoff.
4. **Jira SAML servlet (F-4).** `redirectTo` on `servicedesk-accpt.*`.
5. **`/xui` JWT (F-6).** Decode `am-auth-jwt`, map the claims, look for
   client-side trust.
6. **Subdomain enumeration is a waste of time.** The wildcards are
   **"No bounty"**. Enumerating `*.portofantwerpbruges.com` produces findings you
   cannot be paid for. Only enumerate to *find* a new Tier-2-listed asset, which
   the scope file already gives you in full.
7. **Do not revisit the IP ranges.** Confirmed dead (§2).

### Accounts needed

Nothing above is authenticated except via ACCPT environments, so register
accounts on the `-accpt` apps (`register-accpt.*`, `my-accpt.*`) to get a second
user for IDOR/BOLA work on the API surface (`api-accpt.*`).

---

## 6. Evidence

| File | Contents |
|---|---|
| `intigriti.portofantwerp.scope` | Raw program page / scope table |
| `targets-web.txt` | 45 lines / 44 unique bounty-paying URLs parsed from the scope |
| `runs/2026-09-25_01-04-13/` | Original masscan + nmap output |
| `runs/2026-09-25_01-04-13/masscan.txt` | TCP-only, 0 UDP lines — UDP 500/4500 unscanned |
| `runs/2026-09-25_01-04-13/probe-a-liveness.json` | Raw liveness/fingerprint JSON — 44 targets |
| `runs/2026-09-25_01-04-13/probe-b-hostheader-sweep.json` | Raw Host-header sweep JSON — 225 requests, 5 IPs |

---

## 7. Application layer — `register-accpt` registration flow

Source: Burp Suite export `register-accpt.portofantwerpbruges.com` (99 items,
2026-09-25 18:59–19:08) plus the leaked stack trace in `exception.txt`.

## 7.1 · Product / stack identification

| Layer | Technology | Evidence |
|---|---|---|
| CDN/WAF | Cloudflare | `server: cloudflare`, `cf-ray` |
| LB / ASM | F5 BIG-IP LTM + ASM | `PoABLBaccpt`, `BIGipServer*`, `TS01d85b3*` |
| Internal proxy | **Envoy** | `X-Envoy-Upstream-Service-Time`, `Via: 1.1 <host>` |
| Account/registration app | **Amaris "RAV" / Combase** (Java) | `be.amaris.rav.*`, `be.amaris.combase.managers.rest.impl.*` |
| Runtime | Jetty + RESTEasy + Hibernate, JDK 17 | stack trace frames |
| SSO (login-accpt) | **ForgeRock OpenAM** (XUI) | `/poam/XUI/`, *Copyright 2012-2021 ForgeRock AS* |
| notula-accpt | **Keycloak** realm `suite-antwerpenhavenstg` | `/suite-backend/realm`, `/realms/...` |
| Federation | Keycloak brokers to **Microsoft Azure AD** | `/broker/ms-azure-ad/login` |

`GET /account/api/auth/none` (unauthenticated) returns the RAV module descriptor
`{"module":{"code":"RAV","rav_url":"https://my-accpt..."}}` **and the full i18n
bundle**, which enumerates privileged back-office operations by key:
`rav.company.max.users.changed`, `rav.company.user.access.to.module.given`,
`rav.user.create.external.user.set.admin` ("Set admin"),
`rav.user.create.external.user.set.active`, `addressbook.company.company.updated.apcscode`,
`rav.company.company.closed`. That is a free map of the company/admin module.

### 7.2 · Findings

#### F-8 · Role/activity selection is client-controlled (top lead)

`PUT /account/api/registernewusers/{regId}/application` takes the applicant's
granted roles straight from the request body:

```json
{"id":"APICS",
 "activities_and_codes":{"activities":["AGENT","BRGOPERATOR","EXPEDITEUR","TPLOPERATOR"],
                         "application_codes":[]},
 "selected_communities":[],
 "policies":[{"policy_accepted":true,"policy_guid":"5dc45cb2-..."}]}
```

The UI restricts the applicant to one choice; the **API accepted all four APICS
activities in a single 204-OK request** with no complaint. The server does not
appear to re-derive the role set from the applicant's real business profile.

The catalogue (`GET .../{regId}/applications`, 17 apps, full role definitions)
contains roles that are explicitly meant to be granted only by an authority:

| App | Role | Description |
|---|---|---|
| BTS | `BTS_PORT_OP` | **"Port Authority" — *Only for Port Authorities*** |
| BTS | `BTS_RIS_OP` | **"RIS Authority"** |
| BTS | `BTS_TERMINAL_OP` | Terminal operator |
| RVP | `RAILWAYOPERATOR` | Railway network operator |
| WORKPERMIT (TOOL) | `GASDESKUNDIGE` | Gas expert |
| PORTDUES | `BVR_3_BETALER`, `ZVR_ALR_PRINC` | Maintain financing third parties / berthing dues and principals |

**Hypothesis:** submit `activities:["BTS_PORT_OP"]` (and/or `BTS_RIS_OP`) for
`id:"BTS"` and see whether the server grants an authority role to a self-service
applicant. If it does, that is **vertical privilege escalation** — the exact
first-listed interest of this program (and worth ≥ High). The `application_codes`
field is the likely server-side control: apps that require an issued
authorization code should reject an empty/invented one. Test both.

Status: **untested.** This is a one- or two-request test with the highest
expected value on the board.

#### F-9 · Pre-auth PII read on the registration object (candidate)

`GET /account/api/registernewusers/{regId}` returns the applicant's **personal
data**:

```json
{"id":"QZCZ1LTFBKBIPW8X","secret":"QKVBCMBDJY",
 "email":"<...>","first_name":"<...>","last_name":"<...>",
 "telephone_number":"<...>","policy_accepted":true}
```

**UPDATE — tested and largely closed.** The endpoint requires a second factor that
is *not* the id: the registration `secret`, sent as
`X-Amaris-Registernewusersecret: <secret>`. Reading by id alone fails:

```
GET /account/api/registernewusers/{id}   (no secret header)
  -> 500 {"message":"secret doesn't match",
          "stacktrace":"java.lang.RuntimeException: secret doesn't match
            at be.amaris.rav.service.registernewuser.impl.DefaultRegisterNewUserSecurityHelper.assertSecret(...)}
```

So the capability is the **id + secret pair**, the secret is *not* handed out by an
id-only read, it is never placed in a URL, and neither half is enumerable
(id = 16 × `[A-Z0-9]`, secret = 10 × `[A-Z]`). There is no demonstrated path for
another user's data here. Treat F-9 as **not a finding** unless an id+secret pair
leaks (referrer, e-mail, log, admin listing).

Two residual nits, both out of scope on their own:

- a failed authorisation check returns **HTTP 500 + a stack trace** instead of
  401/403 — sloppy, and a variant of F-10;
- the response differs for an existing id (`secret doesn't match`) versus a
  non-existent one (`registernewuser.not.found`), i.e. an existence oracle. Moot
  while ids are unguessable, and enumeration is explicitly out of scope.

#### F-10 · Unhandled exception leaks internal stack traces (`lostusername`)

`POST /account/api/lostusername` returns HTTP **422** with a JSON body containing
a **full Java stack trace** (`stacktrace` field), unauthenticated:

```
be.amaris.rav.infrastructure.RavExceptionWithDetail: RAV:rav.no.user.for.email([])
  at be.amaris.rav.service.lostusername.impl.LostUsernameResource.lostUsername(LostUsernameResource.java:62)
  at be.amaris.combase.managers.rest.impl.sanitize.RestSanitizeInvocationHandler.invoke(...)
  ... RestPersistenceInvocationHandler, RestStatisticsInvocationHandler,
      RestAuditInvocationHandler, RestValidationInvocationHandler,
      RestPolicyInvocationHandler, RestSecurityInvocationHandler,
      RestMetricInvocationHandler, RestLoggingInvocationHandler ...
  at org.jboss.resteasy.core.SynchronousDispatcher.invoke(...)
```

This is the framework's `RavExceptionWithDetail` behaviour, not an accident: the
class name states that exceptions deliberately carry a **detail** payload (the
`RAV:<i18n-key>` template plus its arguments) so the Angular SPA can render a
translated message. The handler then serialises the whole exception — including
`getStackTrace()` — into `{"message": ..., "stacktrace": ...}`. It is a
developer-detail facility left enabled on an internet-facing profile, and the
Cloudflare/F5 tier does not strip it from 500 JSON responses.

Verdict: as a standalone report this is **out of scope** — *"Verbose messages …
without disclosing any sensitive information"* is an excluded application. It
discloses no filesystem paths (`/opt`, `/var`, `.war`, `.properties`, `.xml`),
no JDBC URLs, no credentials, no SQL, no internal hostnames or IPs, and no PII.
Worth far more as **recon and as supporting context inside an in-scope finding**.

###### What it actually gives you

**1. The authorisation handler chain *and its order*.** Reading the trace from the
method outward (execution order is the reverse — outermost runs first):

```
Logging -> Metric -> Security -> Policy -> Validation -> Audit
        -> Statistics -> Persistence(Hibernate tx) -> Sanitize -> resource method
```

That is a complete map of the security architecture, and two things in it matter:

- **Identity.** Real, ordered `RestSecurityInvocationHandler` (:32) and
  `RestPolicyInvocationHandler` (:39) exist, so authorisation is
  **annotation-driven and evaluated per method**. A resource method that is
  missing or mis-annotated silently gets a no-op handler. Enumerating every
  `/account/api/**` resource and diffing which ones return data
  unauthenticated is the concrete BAC/IDOR hunt.
- **Validation runs *outside* sanitisation.** `RestValidationInvocationHandler`
  is 5th from the outside; `RestSanitizeInvocationHandler` is the innermost
  handler, i.e. it runs **last**, immediately before the method, and its output is
  **never re-validated**. Input is therefore checked in its raw form and then
  mutated by the sanitiser before the method consumes it — the canonical
  validator/consumer mismatch that filters are bypassed with. Unconfirmed
  hypothesis, but it is a structural property of the framework, so it applies to
  every resource at once.

**2. Forced exceptions are a free internal-API enumeration oracle.** Because
*every* `RavExceptionWithDetail` is serialised with a stack trace, triggering an
exception on **any** endpoint enumerates internal class and method names. This
already paid off: the `secret doesn't match` trace (F-9) named the authorisation
helper and its entry point —

```
java.lang.RuntimeException: secret doesn't match
  at be.amaris.rav.service.registernewuser.impl.DefaultRegisterNewUserSecurityHelper.assertSecret(DefaultRegisterNewUserSecurityHelper.java:15)
  at be.amaris.rav.service.registernewuser.impl.RegisterNewUserResource.assertSecret(RegisterNewUserResource.java:542)
```

— i.e. it disclosed *how* registration authorisation is enforced. Deliberately
force exceptions across the API surface to map the rest of the authorisation
logic. Cheap, and one request per endpoint.

**3. It cross-confirms the mechanism behind F-13.** Pairing this trace with the
other 500 (`expected @RestSecurityData or @LoggedInUserRestSecurityData for
resource IRegisterNewUser…`) shows resources must declare where the security
handler *gets* identity: `@LoggedInUserRestSecurityData` (server session) or
`@RestSecurityData` — which is populated from the **client-supplied
`X-Amaris-Securitydata` header**. Any authorisation-sensitive resource annotated
with the latter hands identity control to the caller. That is the whole of F-13,
and this trace is what makes it concrete rather than speculative.

**4. Platform fingerprint.** `be.amaris.{frame,combase,rav}` — Belgian vendor
Amaris, three layers (framework / REST manager chain / RAV module). RESTEasy on
**Jetty**, `javax.servlet` (not `jakarta`) so a pre-Jakarta Java EE stack, JDK 17,
Hibernate session-per-request with rollback-on-exception.
`X-Envoy-Upstream-Service-Time` additionally exposes clean server-side timing with
no network jitter — a ready timing oracle for blind tests.

Caution: the Jetty generation is legacy, and the program explicitly excludes
*"Vulnerabilities that only work on software that no longer receive security
updates"*. Do not chase a Jetty CVE for reward; the framework internals above are
the valuable part.

**5. Input interpolation.** The `[]` in `rav.no.user.for.email([])` is the
user-supplied email interpolated into the message template, which also passes
through `RestLoggingInvocationHandler`. Reflection into the JSON response is
JSON-escaped; the residual angles are log injection / whatever later consumes the
rendered message. Low and usually unrewarded — note it, do not lead with it.

The `lostusername`/`lostpassword` surface is also user enumeration, which is
**explicitly out of scope** — do not report that angle.

#### F-11 · Unauthenticated configuration disclosure (low / likely out of scope)

- `GET notula-accpt/suite-backend/realm` → `{"url":"https://authenticatie-staging.onlinesmartcities.be","realm":"suite-antwerpenhavenstg","client":"suite"}`
- `GET login-accpt/poam/json/serverinfo/*` → realm config: `cookieName: authidaccpt`,
  `secureCookie: true`, `forgotPassword: false`, `forgotUsername: false`,
  `selfRegistration: false`, `xuiUserSessionValidationEnabled: true`

Banner/version/config disclosure is excluded. Recorded for context only.
`/poam/XUI/` returning 200 is **the ForgeRock end-user login page, not an exposed
admin console** — verified, so it is not a management-interface exposure.

#### F-12 · `match` and `company` accept unvalidated business identity

`POST .../{regId}/company` accepts an arbitrary company name, address and VAT
flag, and `GET .../{regId}/match` returns 204. The catalogue reports
`company_admin_can_handle_registration: true`, i.e. the company object drives
who may handle later registrations. This is the surface where a company-match
failure becomes horizontal access to another company's users. **Treat as
untested and sensitive** — see the boundary note below.

#### F-13 · RETRACTED — `X-Amaris-Securitydata` does *not* carry a client-chosen identity

Every XHR the SPA makes carries a required header:

```
X-Amaris-Securitydata: none,RAV,EN
```

Without it the API refuses to serve at all, leaking its own annotation contract:

```
POST /account/api/registernewusers
  -> 500 {"message":"expected @RestSecurityData or @LoggedInUserRestSecurityData
                    for resource IRegisterNewUser..."}
```

**This section previously claimed the first field of that header was a
client-supplied identity and called it the highest-severity lead on the asset.
That was wrong. Retracted on evidence — recorded here so the mistake is not
repeated.**

The header is real and mandatory (it populates `@RestSecurityData`), but the client
**hardcodes** the first field. From the SPA bundle:

```js
this.headerParams["X-Amaris-SecurityData"] = "initial";   // placeholder
// interceptor, on every request:
a.clone({setHeaders: {
  "x-Amaris-SecurityData": "none,RAV," + e.i18n.getApplicationLanguage(),
  "X-Amaris-RegisterNewUserSecret": r.secret }})
```

The literal `"none"` is the *anonymous-context* marker, not a user reference. The
server does not trust it blindly either: probing with anything other than `none`
is rejected, with the offending value echoed back — a server-side **validation**
failure, not a trust failure:

```
X-Amaris-Securitydata: none              -> 500 NoSuchElementException "No value present"
X-Amaris-Securitydata: zzz-not-a-user    -> 500 IllegalArgumentException "zzz-not-a-user,RAV,EN"
X-Amaris-Securitydata: 0                 -> 500 IllegalArgumentException "0,RAV,EN"
X-Amaris-Securitydata: 1                 -> 500 IllegalArgumentException "1,RAV,EN"
```

`none` is recognised and yields "no user in context"; anything else fails to parse.
So the field is a validated *context descriptor* (`anonymous, module, language`),
the real identity comes from the session, and there is no identity spoofing here.

Two genuine, much smaller observations survive, both variants of F-10:

- endpoints annotated `@LoggedInUserRestSecurityData` raise
  `NoSuchElementException` → **HTTP 500** when unauthenticated, where a 401 is
  correct. Sloppy, and unrewarded on its own.
- a distinctive library API exists in the shared front-end library —
  `getUserWithRoleBasedSecurityAndSetAmarisHeader`,
  `getUserWithGroupBasedSecurityAndSetAmarisHeader`,
  `getUserAndSetAmarisHeaderForAllApplicationLanguages`,
  `getUserAndSetAmarisHeaderOnlyForUserLanguage` — meaning the header *does* carry
  real security data in other (authenticated) applications. Out of scope for this
  asset, but it is the same shared library, so the mechanism is worth remembering
  when the authenticated apps open up.

Also noted: the same data appears as a **base64 query parameter** on the policy-PDF
route — `api/mypolicies/{guid}/pdf?securitydata=<btoa(...)>&v=<ts>` — so security
context can travel in a URL (logs, referrers, caches). And a library log line
states security data *"needs to be provided through the policy service"*, which is
what the elevated path in F-14 exists to do.

### 7.4 · Scope corrections from this capture

- `authenticatie-staging.onlinesmartcities.be` appears in the SSO flow but is a
  **third-party host (Online Smart Cities)** and is **not** a listed asset.
  Do not test it.
- `www.portofantwerpbruges.com` served the Matomo analytics endpoint
  (`/stats/matomo.php`) used by the registration page.
- Internal application identifiers differ from the display names used in
  `applications.txt` (`CRP`=Certified Pick-up, `CNCP`=Nautical Chain Planner,
  `EBALIE`=e-Desk customs, `DIGICMR`=eWastra, `ECONTRACTSFWD`=FORWARD e-Contracts,
  `RVP`=Rail Trans Port Manager, `WORKPERMIT`=TOOL). Use the internal ids in API
  calls.
- Apps carrying the `DOUANE` (customs) category, and therefore best avoided:
  `CRP`, `EBALIE`, `DIGICMR`, `IRP`.

### 7.5 · Boundary note (read before testing F-12)

`GET .../{regId}/match` and the company flow associate a registration with a
**real company entity**. If a test registration is matched to an existing
company and that association conveys access to that company's users or data,
**stop, do not download or retain any of it beyond what the report needs, and
report it**. Self-assigning `BTS_PORT_OP` on the acceptance environment is
acceptable authorisation testing; using it to reach real operational data is not.

### 7.6 · Next actions (application layer)

1. **F-8** — submit `BTS` with only `BTS_PORT_OP`, then only `BTS_RIS_OP`, one
   request each. Observe whether the grant succeeds and whether an
   authority-only view appears. Highest value, lowest cost.
2. **F-8b** — for an app that expects `application_codes`, submit an empty and
   then an invented code.
3. **F-9** — search for any endpoint that *lists* registrations (current user's
   company, admin/company module) to establish an id source.
4. **F-10** — enumerate `/account/api/**` unauth reachability; the interceptor
   chain is the BAC surface.
5. Re-do the registration with `eliam@intigriti.me` **first** — everything above
   is worthless if the account is built on a non-`intigriti.me` address.

---

## 8. Registration automation — `poa_register.py`

Written to replace manual re-keying of the wizard after the `.com` address
mistake. Reconstructed from the Burp export; the whole flow is 13 requests.

### How the wizard actually works

Two **undocumented custom headers** are load-bearing. Neither appears in any
client-visible UI, and the API does not work without them:

| Header | Purpose | Failure mode if missing |
|---|---|---|
| `X-Amaris-Securitydata: <identity>,RAV,<lang>` | populates the framework's `@RestSecurityData` annotation | `500 expected @RestSecurityData or @LoggedInUserRestSecurityData for resource IRegisterNewUser...` |
| `X-Amaris-Registernewusersecret: <secret>` | registration-scoped secret issued by `POST /registernewusers` | `500 java.lang.RuntimeException: secret doesn't match` |

The captcha is a **text challenge, 4 characters**, and its key is generated
**client-side**: `Math.random().toString(36).substr(2,10)`. The challenge image is
fetched with `POST .../{id}/captchaimage` (body `{"key": <10 chars>}`, returns
JPEG), and the answer is posted to `PUT .../{id}/captcha` with
`{"key": <same>, "value": <typed>}`, which flips `i_am_a_robot` to `false`.

The script does **not** bypass the captcha. It writes the challenge JPEG to disk
and prompts for the characters — a human stays in the loop. Automated OCR was
attempted and is not reliable on this image (heavy distortion; tesseract produced
no two variants in agreement), which is the correct outcome for an anti-automation
control.

### Enforced controls (in code, not convention)

- **Host allowlist.** Only `register-accpt.*` and `register-test.*` are accepted.
  The production `register.portofantwerpbruges.com` cannot be targeted — the
  constructor raises before any socket is opened.
- **`@intigriti.me` requirement.** The applicant address is regex-checked and the
  run aborts otherwise. This is the specific mistake that prompted the script.
- **4 req/s throttle** (RoE cap is 5).

### Usage

```bash
# browse the 17-application catalogue and their role definitions
./poa_register.py --email eliam@intigriti.me --list-apps

# complete a registration
./poa_register.py --email eliam@intigriti.me \
    --first eliam --last intigriti --phone +3239999999 \
    --company "Test Company BV" --address "Teststraat 1" --city "2030 Antwerp" \
    --app APICS --activities AGENT

# F-13 probe: influence the client-supplied identity field
./poa_register.py --email eliam@intigriti.me --sd-user <identity> --app APICS --activities AGENT
```

### Verified end-to-end

Run on 2026-09-25 completed the full wizard in **13 requests at 4 req/s**:

```
registration VRWCJX1UZTCPCZGR
  submitted=True  i_am_a_robot=False  language=EN
  application=APICS  activities=['AGENT']
```

A confirmation e-mail arrived for **APICS** stating the request is pending
processing, confirming the address used was `eliam@intigriti.me` and not the
earlier `eliam@intigriti.com`. The earlier `.com` draft was never submitted
(`submitted: false`), so no out-of-scope registration was completed.

Note the applicant name given to the company field was neutral test data, not
Port of Antwerp-Bruges' own details, to avoid any impersonation concern (see
§7.5).

File: `poa_register.py` (stdlib only — no dependencies to install).

---

## 9. Exception-oracle API sweep — `poa_api_sweep.py`

Method: derive the route table from the SPA bundle (`/tmp/main.js`, single bundle,
no lazy chunks), then force exceptions on each route and harvest the stack traces.
48 requests, 4 req/s, read-only and malformed input only. `/api/lostpassword` was
deliberately **not** probed (it dispatches e-mail; email bombing is out of scope).
Raw output: `api-sweep.json`.

### 9.1 · Route table recovered from the bundle

```
api/auth  api/auth/none  api/auth/group  api/auth/role
api/countries
api/parameters/{getEnvironment,homelink,supportemailaddress}
api/mypolicies  api/v2/mypolicies  api/mypolicies/{id}/pdf?securitydata=<b64>
api/lostusername  api/lostpassword  api/resetpassword/valid
api/registernewusers
api/registernewusers/policy  api/registernewusers/policy/{guid}/{language}
api/registernewusers/{id}[/{applications,match,personal,company,companyid,
                             application,registrationlanguage,captcha,captchaimage}]
```

Endpoints **not** previously seen and worth noting: `/api/auth/group`,
`/api/auth/role`, `/api/parameters/supportemailaddress`,
`api/mypolicies/{id}/pdf?securitydata=<base64>`,
`api/registernewusers/{id}/companyid`.

### 9.2 · The security handler has two branches, and they behave differently

The `RestSecurityInvocationHandler` frame appears at **two different line numbers**,
which separates two enforcement paths cleanly:

| Frame | Endpoints | Behaviour |
|---|---|---|
| `RestSecurityInvocationHandler.java:30` | `/api/mypolicies`, `/api/v2/mypolicies` | **401 `not.authorized.for.application`** via `DefaultSecurityChecker.checkApplicationAuthorized` → real application authorisation |
| `RestSecurityInvocationHandler.java:32` | 14 endpoints incl. `/api/auth/role`, `/api/auth/group`, `/api/parameters/supportemailaddress`, all of `/api/registernewusers/**`, `/api/lostusername` | reaches the handler, **never calls `checkApplicationAuthorized`**, fails deeper with 500 |

The line-30 path is the enforced one. Everything on line 32 proceeds without an
application-authorisation check — legitimately so for the unauthenticated
registration wizard, but `/api/auth/role` and `/api/auth/group` are different: they
return **the caller's roles and groups**, i.e. authorisation data, and they do so
via `be.amaris.combase.service.auth.AuthResource.getRole(:120)` / `getGroup(:96)`
with **no `checkApplicationAuthorized` on the path**.

### F-14 · Privileged path reachable unauthenticated (lead)

`GET /api/registernewusers/policy/{guid}/{language}` — an unauthenticated route —
executes inside an explicit **system-user** security context:

```
be.amaris.frame.managers.newsecurity.impl.NewSecurityManager.runAsSystemUserSameThread(NewSecurityManager.java:242)
be.amaris.frame.managers.newsecurity.impl.NewSecurityManager.runAsSystemUserSameThreadNoException(NewSecurityManager.java:248)
be.amaris.frame.managers.newsecurity.impl.NewSecurityManager.runAsSameThread(NewSecurityManager.java:295)
be.amaris.frame.managers.newsecurity.impl.NewSecurityManager$DefaultRunAsCallable.call(NewSecurityManager.java:339)
be.amaris.infrasecurity.service.remote.policy.PolicyResourceClient.getPolicyPdf(PolicyResourceClient.java:39)
be.amaris.infrasecurity.managers.policy.impl.PolicyManager.getPolicyPdf(PolicyManager.java:232)
```

Reading: an anonymous caller reaches a code path that **elevates itself to the
system user** and then makes a **remote** call (`infrasecurity.service.remote.*`)
into the policy service, parameterised by two caller-influenced path segments
(`{guid}`, `{language}`). This is consistent with the library log line in F-13
("security data … needs to be provided through the policy service") — the elevation
exists so an anonymous registrant can be shown a policy, which is defensible
design rather than a bug in itself.

Why it is still the top structural lead: two attacker-influenced values flow into a
remote, privilege-elevated call. The candidate classes are parameter injection into
the remote request, and traversal if `{language}` or `{guid}` reaches a path or
filename. Bad-guid handling returns only `SC_INTERNAL_SERVER_ERROR`. **Untested**
beyond a single bad guid; probe read-only, one variable at a time, and expect a
whitelist.

### F-15 · `/api/auth/role` and `/api/auth/group` skip application authorisation (lead, needs a session)

Both sit on the line-32 branch and reach `AuthResource.getRole` / `getGroup`
without `checkApplicationAuthorized`. Unauthenticated they fail with
`NoSuchElementException` because no user is in context — but that means the
**only** thing standing between a caller and their role/group data is the presence
of a user in the session, *not* an application-authorisation check.

The natural test, once the pending APICS account is approved and a session exists:
sign in, and while the application request is **not yet granted**, call
`/api/auth/role`, `/api/auth/group` and the `/api/mypolicies` pair. If the first two
answer while `mypolicies` correctly 401s, that is inconsistent enforcement of
application authorisation on endpoints that disclose authorisation data — a
reportable privilege-escalation/information-disclosure finding rather than a guess.
**Do not test this before approval** — an ungranted account is exactly the state it
needs, so try it then, once.

### 9.3 · Internal symbol map harvested (the reusable output)

Authorisation decision points, now known by name:

```
DefaultSecurityChecker.checkApplicationAuthorized(DefaultSecurityChecker.java:59)
MethodSecurityChecker.checkSecurityWithDefaultApplicationCheck(MethodSecurityChecker.java:22)
NewSecurityManager.{runAsSystemUserSameThread,runAsSystemUserSameThreadNoException,
                   runAsSameThread,$DefaultRunAsCallable.call}
DefaultRegisterNewUserSecurityHelper.assertSecret(DefaultRegisterNewUserSecurityHelper.java:15)
RegisterNewUserResource.{assertSecret(:542),assertNotARobot(:537),getRegisterNewUser(:218),
                        findApplications(:335),findMatch(:265),getPolicyPdf(:142)}
AuthResource.{getRole(:120),getGroup(:96)}
AssertUtils.assertNotBlank(AssertUtils.java:70)
```

Two conclusions worth keeping:

- **Authorisation is per-application**, via `checkApplicationAuthorized` — so
  "do I have the APICS app" is the gate, not "am I a user". Cross-application
  access on a shared codebase is therefore the shape to look for.
- **The captcha is genuinely enforced server-side**: `assertNotARobot` threw
  `expected not a robot, but was true` on `/applications` and `/match`. No captcha
  bypass; drop that idea.

Also confirmed the F-9 correction independently: `GET /api/registernewusers/{id}`
with the secret header → **200 with the data**; without it → `500 secret doesn't
match`; non-existent id → `422 registernewuser.not.found`.

---

## 10. Is this target dry? No — it is gated

### 10.1 · `notula` export — no new material

The 14-item Burp export `notula` (2026-09-25 21:49) re-treads ground already
covered: `GET /` (200), `GET /suite-backend/realm` (200, the Keycloak config),
`GET /suite-backend/walkthrough` (**401**), the Keycloak -> Azure AD broker chain,
and the OpenAM login flow. Nothing new operationally.

Incidental observations only:

- `/suite-backend/*` is uniformly **401** — the whole API needs a session.
- The identity provider is `authenticatie-staging.onlinesmartcities.be`, a
  **third-party host, not a listed asset** — off-limits.
- Accounts are **vendor-provisioned**, not self-service.
- The bundle is Angular and ships **Froala Editor**
  (`node_modules/froala-editor/css/froala_editor.pkgd.min.css`). Froala has a
  history of rich-text sanitisation issues, so *if* authenticated content creation
  is ever reached, stored XSS via the editor is the place to look. Requires an
  account we cannot obtain, so it is a note, not a lead.

**Conclusion: notula is a dead end without an account.** Do not spend more here.

### 10.2 · The real reason progress stopped: everything is behind account approval

| Surface | State |
|---|---|
| IP ranges (`94.107.237.192/26`, `188.118.8.0/25`) | infrastructure only, no app surface |
| VPN / IPsec | client-certificate auth, no pre-auth path |
| `www`, `wiki`, `servicedesk`, `maximo`, `share`, `webapps`, `api`, `apps` | all behind Cloudflare + F5 ASM, all require a session |
| `notula-accpt` | third-party, vendor-provisioned accounts |
| `register-accpt` | **the one self-service surface** — and its registration is manually reviewed |

So the unauthenticated phase is genuinely close to exhausted, but the
**authenticated** phase — where this program's stated interests actually live
(horizontal/vertical privilege escalation, personal data, SQLi) — has not started.
That phase needs one thing: an approved account.

### 10.3 · The unblocked path: `register-test` is live and in scope

The scope file states it outright:

> `register.portofantwerpbruges.com` (NOTE: `register-accpt.portofantwerpbruges.com`
> and **`register-test.portofantwerpbruges.com` are IN scope!**)

Verified live and it is the **same application**:

```
GET register-test.../account/api/auth/none -> 200
  {"module":{"code":"RAV","supported_languages":["DE","EN","FR","NL"],
             "rav_url":"https://my-test.portofantwerpbruges.com/profile/"}}
GET register-test.../account/api/parameters/getEnvironment -> 200 {"value":"POA"}
```

**Correction (2026-09-25 21:56): this does *not* bypass manual review.** A
registration was submitted here (`MAZANENHN5OJCTT0`, APICS/AGENT, `submitted: true`)
and the confirmation mail is the **same pending message** as the accpt one —
*"You will receive a notification as soon as your request has been processed."*
The `-test` environment is manually reviewed too. The assumption that test
environments auto-provision was wrong; both environments are gated on POA staff.

Still worth having: it is a second, independent pending registration, in a separate
database, and `register-test` remains in scope for the unauthenticated leads below.

Scope caveat: `register-test`, `login-test` and `webapps-test` are listed assets.
**`my-test` and `apps-test` are NOT in the asset list** — they fall under the
"No bounty" wildcard, so do not build a report on them.

### 10.4 · Recommendation

Do **not** abandon the target. Move, at most, in parallel. The next actions are:

1. Register on **`register-test`** with the existing automation — fastest route to
   a session.
2. With a session, test **F-15**: `/api/auth/role` and `/api/auth/group` sit on the
   branch that never calls `checkApplicationAuthorized`. Compare them against
   `/api/mypolicies` (which correctly 401s). One request pair decides it.
3. Then attack the **per-application authorisation boundary** — the gate is
   `DefaultSecurityChecker.checkApplicationAuthorized`, i.e. "do I hold app X", not
   "am I a user". Cross-application access on the shared codebase is the shape the
   program pays for, and the scope warns that shared-codebase duplicates are
   collapsed into one finding — so be first.
4. **F-14** (`/api/registernewusers/policy/{guid}/{language}`, system-user path into
   a remote call) remains the only unauthenticated lead that touches privileged
   code. Read-only, one variable at a time.

---

## 11. Where this actually stands (2026-09-25 21:56)

### 11.1 · Both environments are gated on the same manual review

| Environment | Registration | State |
|---|---|---|
| `register-accpt` | `VRWCJX1UZTCPCZGR` — APICS / AGENT | `submitted: true`, awaiting POA review |
| `register-test` | `MAZANENHN5OJCTT0` — APICS / AGENT | `submitted: true`, awaiting POA review |

Both returned the identical pending message. **No session is obtainable without a
POA human approving a registration.** Every authenticated lead (F-15, the
cross-application boundary, F-3/F-4/F-6 on the other hosts) is blocked on that.

### 11.2 · The manual review is itself a compensating control (revises F-8)

F-8 (client-controlled `activities` array) was ranked the top lead on the assumption
that the API grant was the only gate. It is not. Because a **human at POA vets every
registration**, a request self-selecting `BTS_PORT_OP` ("Only for Port Authorities")
would be seen and refused by that reviewer before any role is granted.

So F-8's practical severity is much lower than first assessed: the request-tampering
is real, but an out-of-band human control sits in front of it. To be reportable it
would need evidence the reviewer rubber-stamps role changes, which is not something
to test by impersonating an authority's role request. **Downgrade F-8 to
"informational unless rubber-stamping is demonstrated".** This is a case where the
control is procedural rather than technical, and programmes do not pay for that.

Same logic caps the value of a second "authority role" registration: it burns a
review slot and risks looking like an attempt at real unauthorised access.

### 11.3 · Remaining unauthenticated work — exactly one lead

**F-14** is the only lead that does not need an account:
`GET /api/registernewusers/policy/{guid}/{language}` reaches a code path that
elevates to the **system user** and makes a **remote** call parameterised by two
caller-influenced path segments. It is read-only, in scope on both environments, and
is the only unauthenticated path that touches privileged server code. Bad-guid
returns only `SC_INTERNAL_SERVER_ERROR`, so expect a whitelist — but this is where a
foothold would come from if one exists.

### 11.4 · Recommendation

1. **Do not keep grinding this target unauthenticated.** The surface is exhausted;
   what is left is gated, not undiscovered.
2. **Ask the program for researcher accounts.** All of the declared in-scope value
   (`api`, `apps`, `my`, `wiki`, `servicedesk`, `webapps`, `share`, `maximo`) is the
   authenticated surface. Use the contact button: state that two registrations are
   pending review, and ask whether accounts can be provisioned on the accpt/test
   environments for research. This is a normal, reasonable request and converts an
   indefinite wait into a concrete ask.
3. **Run F-14 now**, while waiting, since it needs no account.
4. **Open a second target in parallel** rather than moving off this one. When POA
   approval lands, the authenticated work here is where this program's stated
   interests (horizontal/vertical privilege escalation, personal data, SQLi) live —
   and the scope collapses shared-codebase duplicates into one finding, so being
   first counts.

---

## 12. F-14 resolved — NEGATIVE (no foothold)

Probed `GET /api/registernewusers/policy/{guid}/{language}` on both environments,
read-only, one variable at a time. 66 requests total. Raw: `f14-probe.json`.

### 12.1 · The parameters are safe selectors, not paths

`{language}` behaves as a **whitelist lookup with a fallback**, which is the
opposite of path construction:

| Input | Result |
|---|---|
| `EN` | 200, 348777 B (the actual EN document) |
| `NL`, `XX`, `x`, `EN2`, `AAAA…` (200 chars) | 200, **395060 B** — the *same* fallback document for every one of them |
| `` (empty) | 404 — no route match for `{guid}/` |
| `EN/pdf` | 404 |

An unknown language returns a **valid fallback PDF**, not an error, and the response
always carries a fixed `content-disposition: inline;filename=termsandconditions.pdf`.
If `{language}` were interpolated into a path or filename, an unknown value would
404/500 instead of yielding a working document. It is a document *selector*.

`{guid}` likewise selects a policy record: a well-formed but non-existent UUID
(`00000000-…`) fails exactly like a malformed one, so it is a key lookup.

The documents themselves are static: 22-page Word-generated T&C files, created
2021-09-01, byte-identical across both environments for the same language.

### 12.2 · Traversal is mitigated at the edge, and no encoding reaches the origin

Ten traversal encodings on each parameter. **None** reached the origin — no
`stacktrace` JSON, no PDF, every one stopped at the WAF:

| Encoding | Result |
|---|---|
| `../`, `../../../../etc/hostname` | 403 (246 B) / 400 (155 B) — normalised at edge |
| `..%2f..%2f…`, `%2e%2e%2f…`, `....//…` | 403 (4559 B) — F5 ASM / Cloudflare block page |
| `..%252f` (double-encoded), `..%5c` (backslash) | 403 (4559 B) / 403 (246 B) |
| `%c0%ae%c0%ae%c0%af` (overlong UTF-8) | 403 (246 B) |
| `%uff0e%uff0e%uff0f` (fullwidth), `..%2f…%00.png` | 400 (155 B) |
| `..;/`, `.%2e/`, `EN%252f..%252f…` | 403 (4559 B) |

So the WAF is genuinely configured to block traversal on this route, and the
origin's own handling is **not determinable through the front door**. Combined with
12.1 (selectors, fixed filename, whitelist fallback), the likelihood that any
traversal exists behind the WAF is low.

### 12.3 · The system-user elevation is defensible

`runAsSystemUserSameThread` exists on this path because an anonymous registrant has
no rights to fetch a policy document, so the server elevates *itself* to serve a
public T&C. The elevation is a design decision, not a flaw, and with both parameters
acting as safe selectors there is nothing to steer it with.

### 12.4 · Considered and rejected — do not report

The PDF carries `Author: <a person's name>` in its document metadata (along with
`Microsoft Word for Microsoft 365`, created 2021-09-01). This is a real
metadata leak but the program explicitly lists **"Not stripping metadata of files"**
as an out-of-scope application. **Not reportable.** Recorded so it is not
re-discovered and filed.

### 12.5 · Consequence

**F-14 was the last unauthenticated lead. There is no foothold.** The
unauthenticated attack surface of this target is now exhausted:

| Area | Status |
|---|---|
| IP ranges, VPN | no app surface / client-cert auth — closed |
| `notula-accpt` | third-party, vendor accounts — closed |
| `register-accpt` / `register-test` unauthenticated API | swept; leaked stack traces are out of scope; id+secret model holds; captcha enforced |
| F-8 role tampering | real but capped by manual review (§11.2) |
| F-9 | closed — secret is enforced |
| F-13 | retracted |
| F-14 | closed — WAF-mitigated, safe selectors |

Everything remaining requires an approved account, which is a **human queue**, not a
technical obstacle.
