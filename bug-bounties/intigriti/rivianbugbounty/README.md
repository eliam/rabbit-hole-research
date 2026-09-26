# Rivian Bug Bounty — Intigriti engagement notes

Running notes for the **Rivian Bug Bounty** program on Intigriti
(Public / Open, Manufacturing – Consumer). Reference: `rivianbugbounty.RoE`.
All testing stayed within the published RoE.

Rivian designs and manufactures electric vehicles. The RoE is explicit that **the
vehicles themselves are not in scope**; the program covers the web/API estate and
the consumer mobile apps. Tiers range from $100 to $5,000 (Tier 1 / Tier 2).

**Outcome: no payable finding; two weak candidates held back from submission.** The nine
listed Tier-1/Tier-2 assets, the `*.rivian.com` wildcard, all seven HTTP GraphQL
endpoints, the consumer app (178 operations) and the captured session were enumerated
and tested. **The high-value surfaces are all correctly gated** — Fleet and Basecamp
(Entra ID), the consumer vehicle/key/PIN/payment/order/upload/PII operations
(`UNAUTHENTICATED`), and the subscription WebSocket (`4400`). The only items that clear
the *finding* bar are **§32** (Tier-1 Fleet internal-topology disclosure) and **§29**
(anonymous CRM/identity write), and **both are realistically Low, most likely dismissed**
— the RoE excludes verbose errors, enumeration, banner disclosure and API-key
disclosure by name, which covers most of what the surface yields.

**Honest assessment: this scope is unlikely to pay without owner-supplied access.** The
reason is structural, not a lack of effort — see *Reportability* and *Next*. The single
most important *process* result is **not** a bug: this engagement's own scaffold
(`README.md` + `AGENTS.md`) disagreed with the RoE about **eight hostnames** and asserted
an **IP-range gate that does not exist**. See *Scope* and *Housekeeping*.

**This engagement is paused, not closed.** The consumer account surface is now
reachable and three **pre-auth, in-scope** lines of enquiry remain open (*Next*
§1–5). The **single most valuable target** is entitlement enforcement on the
**interior-camera / Gear Guard live-stream** path (§21) — but it is **vehicle-gated
and therefore unreachable without the program owner's help** (*Next*, credential
section). The strongest *reportable-class* item is the **`goriv.co` trust boundary**
(§25), which one shared identity plane trusts in two places — Fleet and the partner
portal federate to the same Entra tenant (§27).

> Verify every line below against `rivianbugbounty.RoE`. Where this file and the
> RoE disagree, **the RoE wins**.

---

## Rules of engagement (observed)

| RoE panel row (verbatim, `rivianbugbounty.RoE` lines 483-491) | Value |
| --- | --- |
| `@intigriti.me` | `Required` |
| `User agent` | `Not applicable` |
| `Automated tooling` | `Not applicable` |
| `Request header` | `X-Intigriti-Username: <Your Username>` |

The scrape preserves the panel rows but not their label/value column alignment, so
the raw block is quoted in `recon/roe-extract-scope.txt` for audit rather than
paraphrased. What is unambiguous:

- **Request header — the only "Required" item:** `X-Intigriti-Username: eliam`.
  Sent on **every** request in this pass. The header value is the operator's
  Intigriti username; the RoE's FAQ (lines 759-760) independently confirms the
  account convention: *"please don't forget to use your @intigriti.me address."*
- **User agent: "Not applicable".** No UA is mandated. A truthful, ordinary
  browser UA was nevertheless sent — CDNs routinely `403` a bare `curl` UA, which
  would have produced false negatives. The exact string is pinned in
  `recon/probe-http.sh`.
- **Automated tooling: "Not applicable".** No tooling clause applies.
- **Rate limit: the RoE publishes NONE.** There is no `Rate limit` row, and no
  numeric cap anywhere in the 911-line file. This is *not* licence to hammer:
  - the RoE bans **DoS/DDoS and brute force** attacks (line 722), and
  - it explicitly excludes *"Bypassing rate-limits or the non-existence of
    rate-limits"* from bounty (line 690) — a missing rate limit is not a finding.
  - **Self-imposed cap: 1 request/second, enforced in `recon/probe-http.sh` via a
    timestamp state file.** **~200 HTTP requests in total** across four passes
    (14:24 → 14:57), all spaced >= 1 s apart. The CT-log query itself is one
    request to `crt.sh`, not to Rivian.
- **Method discipline:** `GET` / `HEAD` / `OPTIONS` only, plus **one** minimal
  read-only GraphQL query per endpoint (`{"query":"{__typename}"}`). No batching,
  no aliases, no recursive/depth probes, no payload fuzzing — the RoE names
  *"GQL Alias overloading, GQL Query depth"* specifically (line 722).
  **No path wordlisting or directory brute force was performed anywhere**, including
  on the wildcard hosts that returned `404` at the root.
- **No port scanning.** `tools/enum/masprobe.py` (masscan + nmap) was deliberately
  **not** used. It takes CIDR ranges; the RoE publishes none, and every in-scope host
  resolves to CloudFront/EC2 addresses — scanning them would hit AWS infrastructure
  rather than Rivian services.
- **Credentials were not obtained.** The FAQ describes a self-registration flow
  (`rivian.com/connect/tell-us-more` → `rivian.com/auth/forgot` → confirm → OTP)
  requiring an `@intigriti.me` mailbox. No such mailbox is available to this
  operator, so **the entire authenticated surface is untested** (see *Not testable*).
- **Safe harbour applies** (RoE lines 515-522). No DoS, no social engineering, no
  physical intrusion, no spam.

---

## Scope

In-scope assets, exactly as listed in the RoE asset table (lines 544-601):

| Tier | Asset | Type | Notes |
| --- | --- | --- | --- |
| Tier 1 | `https://business.rivian.com/api` | URL | Fleet-customer portal API. RoE: *"primary testing for this domain is the authentication/authorization of the publicly available endpoints"* |
| Tier 1 | `https://rivian.com/api/gql/content/graphql` | URL | GraphQL |
| Tier 1 | `https://rivian.com/api/gql/gateway/graphql` | URL | GraphQL gateway |
| Tier 1 | `https://rivian.com/api/gql/orders/graphql` | URL | GraphQL |
| Tier 2 | `*.rivian.com` | Wildcard | **No IP-range constraint is stated** — see below |
| Tier 2 | `rivian.com` | URL | Apex |
| Tier 2 | `basecamp.rivian.com` | URL | Partner/supply-chain portal. RoE: *"we do not provide an option for customers or security researchers to create credentials … the scope of testing for this domain is authentication bypass"* |
| Tier 2 | `1570215232` | iOS | App Store track id |
| Tier 2 | `com.rivian.android.consumer` | Android | Play Store package |

### Scope trap — read this before resuming

**The RoE marks eight hostnames "Out of scope" in the very same asset table.** The
scaffolded `README.md` and `AGENTS.md` for this folder listed all eight as *in-scope
assets*. They are not. This is the trap, and it would have produced out-of-scope
traffic on the first unpicking of the list.

| Host | RoE verdict | Authority |
| --- | --- | --- |
| `assets.rivian.com` | **Out of scope** | asset table, line 579 |
| `careers.rivian.com` | **Out of scope** | asset table 580-581; prose 659 |
| `demovehicles.rivian.com` | **Out of scope** | asset table 583-584; prose 662 |
| `feedback.rivian.com` | **Out of scope** | asset table 586-587; prose 665 |
| `internalshop.rivian.com` | **Out of scope** | asset table 589-590; prose 666 |
| `media.rivian.com` | **Out of scope** | asset table 592-593; prose 660 |
| `stories.rivian.com` | **Out of scope** | asset table 595-596; prose 661 |
| `view.e.rivian.com` | **Out of scope** | asset table 598-599; prose 664 |
| `cloud.e.rivian.com` | **Out of scope** | prose 663 (third-party infrastructure) |

The RoE's prose OOS clause (lines 656-658) is categorical: *"Third party
infrastructure and redirects are out of scope and not eligible for bounty."*
**None of the above was resolved, fetched, or otherwise touched.**

Second trap: **`goriv.co`.** TLS certificates for in-scope hosts advertise a whole
sibling estate — `dc.goriv.co`, `prod.goriv.co`, `*.ue1.origin.prod.goriv.co`,
`*.dc.goriv.co` (`recon/tls-certs.txt`). `goriv.co` is **not** in the RoE scope. It
was never resolved and never touched.

Third trap: **`rivianservices.com`.** The Android app calls
`https://api.rivianservices.com/tiling/*` for map tiles (§22). That is a **different
registrable domain** from `rivian.com`, so it is **outside the RoE** despite being
first-party in intent. Never resolved, never touched. Same class of trap as
`goriv.co` — and note both were surfaced by *first-party* artefacts (a certificate
and the app itself), which is exactly how a wildcard-scoped engagement leaks
out-of-scope hosts.

### Scope discipline note — the phantom IP-range gate, and how the wildcard was bounded

`AGENTS.md` states: *"`*.rivian.com` — subdomain enumeration is in scope **within the
stated IP range(s) only**. Both conditions must be met; a hostname alone is not enough."*

**The RoE states no IP range.** Exhaustive search of the file returns **zero**
IPv4 addresses, zero CIDRs, and no "IP range" / "netblock" / "ASN" language at all:

```
$ grep -nEc '([0-9]{1,3}\.){3}[0-9]{1,3}|/[0-9]{1,2}[^0-9]|CIDR' rivianbugbounty.RoE
0
$ grep -ni 'ip range\|IP address\|netblock\|ASN' rivianbugbounty.RoE
(none)
```

So the second condition of that sentence is **unsatisfiable as written**, and the
`AGENTS.md` premise ("the RoE contains … IP range(s)") is factually wrong. Per this
engagement's own rule — *"If anything below disagrees with the RoE, the RoE wins"* —
the RoE governs, and it lists `*.rivian.com` as an in-scope Tier-2 wildcard **with no
IP constraint**.

**Decision taken (operator, 2026-09-26): enumerate the wildcard, bounded by documented
rules.** The `AGENTS.md` gate is still flagged as defective for whoever owns it, but
it does not veto an asset the RoE lists as in scope. The bounds actually applied:

1. Only names matching `\.rivian\.com$` were considered. `goriv.co` was never resolved.
2. The 8 asset-table carve-outs + `cloud.e.rivian.com` were removed **before** any probe.
3. Hosts whose **CNAME proves a third-party SaaS platform** were removed — the RoE
   puts third-party infrastructure out of scope, and a CNAME to `shops.myshopify.com`
   is proof, not a guess.
4. Hosts that are the `www.`/`staging-` counterpart of a named carve-out were removed
   (e.g. `www.careers.rivian.com` → `*.career.page`), so the carve-out cannot be
   sidestepped by a hostname prefix.
5. **No path wordlisting, no directory brute force, no fuzzing** — root-level
   fingerprinting only.

Counts (detail in `recon/ct-summary.txt`):

| Stage | Count |
| --- | --- |
| CT records (one `crt.sh` query) | 1,864 |
| Unique hostnames (wildcards stripped) | 121 |
| … of which `*.rivian.com` | 120 |
| − RoE carve-outs (+`cloud.e`) | −9 |
| − `www.`/`staging-` carve-out kin | −1 |
| − proven third-party SaaS (CNAME) | −11 |
| **In-scope candidates probed** | **33** |
| Live (HTTP answered) | 22 |
| DNS-only, no listener on 443 | 11 |

---

## Environment / architecture

Everything in scope sits behind **AWS edge infrastructure**, with DNS in **Route 53**
and origins on **S3** / **nginx** / Node.

| Host | Resolves to | Fronting | Origin |
| --- | --- | --- | --- |
| `rivian.com` | `18.154.84.{14,54,95,100}` | CloudFront (`x-amz-cf-pop: LHR5-P7`) | Next.js app |
| `business.rivian.com` | `52.85.47.{15,63,73,107}` | CloudFront (`LHR86-P3`) | nginx → Vite SPA + Cosmo Router |
| `basecamp.rivian.com` | `54.230.201.{46,54,99,109}` | CloudFront (`LHR82-P3`) | **AmazonS3** (`server: AmazonS3`, AES256) |
| `www.rivian.com` | `216.137.53.{18,68,78,93}` | CloudFront | Next.js app (`308` → apex) |
| `api.rivian.com` | `52.85.47.{19,58,79,90}` | CloudFront | nginx (`404`, `x-riv-env: prod_ue1`) |
| `things.api.rivian.com` | `18.211.175.205` | — | **AWS API Gateway** (`x-amzn-RequestId`) |
| `events.rivian.com` | `151.101.{2,66,130,194}.133` | Fastly | **DataDome** bot protection |
| `legacy.basecamp.rivian.com` | `dq32rxk7nudo4.cloudfront.net` | CloudFront | *(referenced by in-scope JS; not a listed asset — not probed)* |

Every API response carries an environment banner: **`x-riv-env: prod_ue1`**.

### Application inventory

| Asset | Stack | Evidence |
| --- | --- | --- |
| `rivian.com/` | **Next.js**, locale-prefixed (`/en-GB/`), locale set by a CloudFront Function | `307` + `x-cache: FunctionGeneratedResponse`, `riv-detected-locale` cookie |
| `rivian.com/{auth,quad,root}/` | Three separate **Next.js** sub-apps under `_next/static` | `404`/`200` bodies; `/root/*` is `noindex` |
| `rivian.com/api/gql/gateway/graphql` | **Cosmo Router** (WunderGraph federated GraphQL) | introspection-disabled message names Cosmo |
| `rivian.com/api/gql/content/graphql` | **Apollo Server** (Express + Datadog) | Apollo CSRF message + `x-datadog-*` |
| `rivian.com/api/gql/orders/graphql` | **Apollo Server** (Express) | explicit Apollo introspection message |
| `business.rivian.com/api` | **Cosmo Router** (federated GraphQL) | explicit Cosmo introspection message |
| `api.rivian.com/graphql` | **Cosmo Router** — found *only* in the APK DEX, invisible to path probing | `400 empty request body`; identical profile to `business` |
| `rivian.com/api/vs/gql-gateway` | **Cosmo Router** — also APK-only; "vs" ≈ vehicle services | same profile; absent from `robots.txt` |
| `wss://api.rivian.com/gql-consumer-subscriptions/graphql` | **GraphQL-over-WebSocket subscriptions**, `graphql-transport-ws` only | `101` upgrade; `connection_init` refused `4400` (§23) |
| `business.rivian.com/graphql` | **second GraphQL entry point** on the same host | same `{"errors":[{"message":"empty request body"}]}` shape as `/api` |
| `business.rivian.com/api/v2/*` | **Go service** — a third backend on the same host | `404 page not found` (19 B, Go's `http.NotFound`) |
| `business.rivian.com/auth/` | **Vite** SPA, "Login"; **MSAL.js → Entra ID** tenant `f798cb4f-b8b7-45f7-ad25-1ff5f130070a` | `/auth/assets/index-DpzK5Jvt.js` (1.2 MB), `login.microsoftonline.com/f798cb4f-…` |
| `basecamp.rivian.com/` | **React** shell: Datadog RUM + session-replay SDK and module federation | `main.js` (319,861 B), `webpackChunkbasecamp_shell` |
| `legacy.basecamp.rivian.com/` | **module-federation remote exposing a component library** | `remoteEntry.js` → `./App ./atoms ./molecules ./organisms ./templates ./ions ./chatbot ./useLegacyStore ./tooling-notification` |
| `login.basecamp.rivian.com/` | **"Basecamp Sign In"** — Vite SPA, `noindex,nofollow`, OAuth2+PKCE → Cognito | `assets/index-M1gWgwGR.js` (428,334 B); **new host, not in CT** |
| `commauth.basecamp.rivian.com/prod` | **AWS API Gateway** custom domain → auth REST API | `403 {"message":"Missing Authentication Token"}`; **new host** |
| `rivian.com/consumer-ui/v1/user` | **BFF user endpoint** — `200 null` unauthenticated, object when authenticated | APK/capture-only path |
| `rivian.com/api/datahub/v1/analytics/publish` | **unauthenticated analytics ingest**, `202` | seen 74× in the capture |
| `rivian.com/api/user-segment` | `307` → `/en-GB/…` then `204` | segmentation endpoint |

Two distinct GraphQL generations coexist: **Cosmo Router** fronts the federated
graph on both `gateway` and `business`, while `content` and `orders` are direct
**Apollo Server** instances. That matters — the security defaults differ.

⚠️ **Correction.** An earlier draft of this README described `/api/v2/` as
`basecamp.rivian.com`'s business API base path. It is not: `/api/v2/{logs,rum,replay}`
is the **Datadog RUM intake proxy** (`createEndpointBuilder` → `ddforward`), and the
only `"password"`/`"email"` strings in `main.js` are Datadog input-masking rules, not
a login form. `/api/v2/` on `business.rivian.com` is a *separate* Go service. There is
**no statically recoverable Basecamp business API in the pre-auth bundles.**

DNS also reveals a large third-party SaaS estate via public TXT records
(`recon/dns.txt`): Google Workspace (MX), and verification tokens for Stripe,
DocuSign, Shopify, Twilio, MongoDB, OneTrust, Dynatrace, Cisco, Atlassian,
Smartsheet, and others. Public data, no secrets, and **not** a finding.

---

## Findings

**No *finding*-tier item exists.** Nothing below is submittable. They are recorded
as controls that are working correctly (*hardening*) and as observations
(*informational*) that the RoE disqualifies on its face.

### 1. *hardening* — GraphQL introspection is disabled on all four endpoints

Four different GraphQL servers, four independent refusals. Verified with a single
standard introspection query each; raw bodies in `recon/graphql-introspection-{gateway,content,orders,business}.json`.

| Endpoint | Response |
| --- | --- |
| `orders` | *"GraphQL introspection is not allowed by Apollo Server … pass `introspection: true`"* (`INTROSPECTION_DISABLED`) |
| `business.rivian.com/api` | *"GraphQL introspection is disabled by Cosmo Router … set `introspection_enabled: true`"* |
| `gateway` | `400` `GRAPHQL_VALIDATION_FAILED` — *"Error in GraphQL validation"* |
| `content` | `400` `GRAPHQL_VALIDATION_FAILED` — *"Invalid request."* |

A correct production default. The schema is not exposable via introspection, so
**the application surface could not be mapped from the schema** — see *Not testable*.

### 2. *hardening* — Apollo Server CSRF preflight is correctly enforced

`content` and `orders` reject a `GET`-borne query with a precise, correct error:

> *"This operation has been blocked as a potential Cross-Site Request Forgery (CSRF).
> Please either specify a 'content-type' header (with a type that is not one of
> application/x-www-form-urlencoded, multipart/form-data, text/plain) or provide a
> non-empty value for one of the following headers: x-apollo-operation-name,
> apollo-require-preflight"*

This is Apollo's simple-request/CSRF defence working as designed. Both endpoints
returned `200 {"data":{"__typename":"Query"}}` once a JSON content-type was supplied.
A `GET` with no body yields `400 GET query missing.` on the Cosmo-fronted `gateway`.

### 3. *hardening* — CORS allow-list is exact and non-reflective (with a positive control)

`gateway` and `orders` send `access-control-allow-credentials: true`, so the only
question that matters is **whether an attacker origin is reflected**. It is not.

| Origin sent | `Access-Control-Allow-Origin` | Verdict |
| --- | --- | --- |
| `https://evil.example` | *(absent)* | rejected |
| `https://rivian.com.evil.example` | *(absent)* | rejected |
| `null` | *(absent)* | rejected |
| **`https://rivian.com`** | **`https://rivian.com`** | **accepted — positive control** |
| `https://www.rivian.com` | *(absent)* | not allow-listed |

The positive control is the point: `ACAO` **does** appear for the legitimate origin,
which proves the negative results are a real allow-list and not an endpoint that
simply never emits `ACAO`. `business.rivian.com/api` answers a forged-origin `OPTIONS`
with `403`. Full matrix in `recon/cors-probe.txt`.

### 4. *hardening* — subdomain takeover checked on the two stub hosts: not vulnerable

`gogoogle.rivian.com` and `googleguide.rivian.com` both resolve and serve a **686-byte
S3-hosted redirect stub** with `server: AmazonS3`. Both targets were verified live and
Rivian-controlled, so there is **no takeover**:

| Host | `meta refresh` target | Target ownership |
| --- | --- | --- |
| `gogoogle.rivian.com` | `https://www.riviancurrent.com/page/3646` | `riviancurrent.com` — registrar **COM LAUDE** (corporate brand-protection), NS = AWS Route 53, CNAME → **`rivianprod.service-now.com`** ⇒ Rivian-owned ServiceNow portal |
| `googleguide.rivian.com` | `https://sites.google.com/rivian.com/guide` | Google Sites under Rivian's own Workspace tenant |

The RoE puts *"Subdomain takeover"* out of scope regardless (line 706); recorded here
because the first-glance signal (a `*.rivian.com` host 302-ing users to a
non-`rivian.com` domain) looks alarming and should not be re-derived.

### 5. *informational* — eleven internal-only hostnames are published in public DNS

Eleven `*.rivian.com` names resolve but **nothing listens on 443**. The DNS records
still disclose internal naming, topology and (for some) private/public origin IPs:

| Host | Resolves to | Note |
| --- | --- | --- |
| `controller.ue1.prod.rivian.com` | `52.86.233.163`, `54.197.147.198`, `13.219.120.249` | **prod** controller names → public EC2 IPs, no listener |
| `controller.uw2.prod.rivian.com` | `44.241.46.133`, `34.214.35.163`, `44.224.28.62` | same, west region |
| `cid.rivian.com` | `44.229.137.88` | direct EC2 |
| `granite.p.rivian.com` | `3.131.203.90` | direct EC2 |
| `limestone.p.rivian.com` | `3.128.122.228` | direct EC2 |
| `ccc.api.dev.rivian.com` | `50.17.164.221` | direct EC2 |
| `dashboard.rivian.com` | CloudFront (`d2vnmr69i2b1wi`) | no listener |
| `em.rivian.com` | `137.22.234.205` | likely email platform |
| `things.dev.rivian.com` | `axjfw2uv2wsmh-ats.iot.us-east-1.amazonaws.com` | **AWS IoT** endpoint, no listener |
| `useast.guestlogin.rivian.com` / `uswest.guestlogin.rivian.com` | `100.64.101.1` / `100.64.102.1` | **RFC 6598 CGNAT** — not routable |

**RoE-ineligible:** internal naming is not "sensitive information" under
*"Verbose messages/files/directory listings without disclosing any sensitive
information"* (line 681), and banner/topology disclosure is excluded outright
(line 703). **No finding** — recorded so the names are not re-chased.

### 6. *informational* — `things.api.rivian.com` is AWS API Gateway, root returns 404

`things.api.rivian.com` and `things.stage.rivian.com` answer with AWS API Gateway
signatures — `x-amzn-RequestId`, `x-amzn-ErrorType: ResourceNotFoundException`, body
`{"message":"Not Found","traceId":"…"}`. Root path only; **no path enumeration was
performed** (that would be brute force). Matches the RoE's *"GQL Query depth /
Alias overloading"* caution in spirit — left as a lead.

### 7. *informational* — email-marketing infrastructure on `link` / `em` / `go`.rivian.com

`link.rivian.com` returns `404` with **`server: msys-et`** — Message Systems /
SparkPost click-tracking infrastructure. `em.rivian.com`, `go.rivian.com` and
`link.rivian.com` all sit on the same Fastly anycast range
(`151.101.{2,66,130,194}.133`). This is **third-party email infrastructure**, out of
scope under line 656, and **none of the three was probed further**.

### 8. *informational* — `x-riv-env: prod_ue1` environment banner on every API response

All four GraphQL endpoints disclose the deployment environment on every response.
**RoE-ineligible**: *"Banner grabbing/Version disclosure"* is explicitly out of
scope (line 703). Recorded because it is useful for orienting across prod/staging.

### 9. *informational* — Datadog trace correlation identifiers on `content` and `orders`

`content` and `orders` return `x-datadog-trace-id`, `x-datadog-parent-id`,
`x-datadog-tags` and W3C `traceparent`/`tracestate`. These are observability
correlation IDs, not secrets and not sensitive data — the caller already holds them
for its own request. **No finding.**

### 10. *informational* — wildcard CORS on `basecamp.rivian.com` static HTML

The SPA shell is served from S3 with `access-control-allow-origin: *` and
`access-control-allow-methods: GET`. The affected resource is **static public HTML
with no authenticated content**, which the RoE excludes directly:
*"CORS misconfiguration on non-sensitive endpoints"* (line 683). **No finding.**

### 11. *informational* — `robots.txt` publishes internal API namespaces

`https://rivian.com/robots.txt` discloses: `/api/`, `/auth/api/`, `/account/api/`,
`/demo-drive/api/`, `/experience/api/`, `/quad/api/`, `/root/api/`, plus
`/experience/r1t`, `/experience/r1s`, `/trip-visualizer`. This is **intentional
disclosure** — the file exists to tell crawlers what not to index. Each namespace
was checked (see *Tested and found clean*). **No finding.**

### 12. *informational* — certificate SANs expose the out-of-scope `goriv.co` estate

`business.rivian.com` is served under `CN=prod.rivian.com` with SANs spanning
`*.rivian.com`, `prod.rivian.com`, and a parallel `goriv.co` family
(`*.dc.goriv.co`, `prod.ue1.dc.goriv.co`, `*.ue1.origin.prod.goriv.co`, …).
`goriv.co` is **not in scope** and was not touched. Recorded only so a future tester
does not mistake the SAN list for a target list. **No finding.**

### 13. *informational* — `legacy.basecamp.rivian.com` is a component-library remote

`https://basecamp.rivian.com/main.js` loads a module-federation remote from
`https://legacy.basecamp.rivian.com/remoteEntry.js`. That host resolves
(`dq32rxk7nudo4.cloudfront.net`) and **is in scope** — it matches the in-scope
`*.rivian.com` wildcard, is not one of the nine carve-outs, and is not `goriv.co`.
It was therefore fetched under the boundary rules in *Scope*.

It returns **`200`, 15,466 B, `application/javascript`**, and exposes a **design-system
/ component library**, not an API: `./App`, `./atoms`, `./molecules`, `./organisms`,
`./templates`, `./layouts`, `./ions`, `./svg`, `./formik`, `./react-hook-form`,
`./chatbot`, `./not-found`, `./useLegacyStore`, `./tooling-notification`, with
`publicPath = https://legacy.basecamp.rivian.com/`. The two names worth revisiting
later are **`useLegacyStore`** and **`tooling-notification`**. No credentials, tokens
or endpoints are exposed by the remote itself. **No finding.**

### 14. *informational / hardening* — `business.rivian.com` emits a session cookie scoped to `Domain=.goriv.co`

Every `302` from `business.rivian.com` carries two cookie deletions aimed at a
**different registrable domain**:

```
set-cookie: session=deleted; Max-Age=0; Domain=.goriv.co
set-cookie: session_prod=deleted; Max-Age=0; Domain=.goriv.co
```

`goriv.co` is not in the RoE scope and is not a Rivian-listed asset. This tells us the
Fleet portal and a `*.goriv.co` deployment **share application configuration and a
session cookie name**, which is why the header is emitted from `business.rivian.com`
at all.

**Impact analysis — deliberately conservative.** Per RFC 6265 §5.3, a user agent
accepts a `Domain` attribute only if it domain-matches the request host — and
`business.rivian.com` does **not** domain-match `.goriv.co`. So conforming browsers
**discard** these headers and there is **no exploitable effect from this host**. It is
a configuration smell, not a vulnerability.

The reason it is recorded rather than dismissed: the *converse* direction is where the
risk would live. If any `*.goriv.co` host can set a `session` cookie for `.goriv.co`
and any `business`/`goiv.co` component *reads* it, then a foothold on any `goriv.co`
host becomes session fixation into Fleet. **That cannot be tested from here** — the
`goriv.co` estate is out of scope and was never touched. Flagged as a lead for the
program owner, not as a finding.

### 15. *informational* — `business.rivian.com` is four backends behind one hostname

| Path | Backend | Evidence |
| --- | --- | --- |
| `/api` | Cosmo Router (GraphQL) | `400 empty request body`; Cosmo introspection message |
| `/graphql` | **a second GraphQL server** | identical `400 {"errors":[{"message":"empty request body"}]}` |
| `/api/v2/*` | **Go** service | `404 page not found`, 19 B, `text/plain` |
| `/auth` | Vite SPA (`200`, 400 B) + HAProxy stickiness cookie | `set-cookie: route=1790430757.482...; Secure; HttpOnly` |

The `/graphql` entry point is **not disclosed** by the SPA bundle, `robots.txt`, or the
RoE — it was found by probing. Two GraphQL entry points mean two independent policy
sets: a Cosmo Router rule that gates `/api` need not gate `/graphql`. **Any
authorization testing on this Tier-1 host must cover both paths.** The HAProxy `route`
cookie and the `x-riv-env: prod_ue1` banner are informational.

### 16. *hardening* — operation-method enforcement differs between the two Cosmo routers

All four GraphQL endpoints were run through the same battery
(`recon/graphql-all4.txt`). The full matrix:

| Probe | `gateway` (Cosmo) | `content` (Apollo) | `orders` (Apollo) | `business/api` (Cosmo) |
| --- | --- | --- | --- | --- |
| `POST { __typename }` | `200 Query` | `200 Query` | `200 Query` | `200 Query` |
| `POST mutation { __typename }` | `200 Mutation` | `200 Mutation` | `200 Mutation` | `200 Mutation` |
| `GET ?query={ __typename }` | **`200` executes** | `400` CSRF block | `400` CSRF block | **`200` executes** |
| `GET ?query=<APQ hash>` | **`200`** PQNF | `400` CSRF block | `400` CSRF block | **`200`** PQNF |
| `GET ?query=mutation {…}` | **`405` `INTERNAL_SERVER_ERROR`** | `400` CSRF block | `400` CSRF block | **`405` "Mutations can only be sent over HTTP POST"** |
| `{ _service { sdl } }` | generic rejection | generic rejection | `Cannot query field` | `Cannot query field` |

Three things fall out of this:

1. **Positive — mutations are refused over `GET` on all four.** The
   GraphQL-over-HTTP rule that mutations must use `POST` is honoured everywhere, so
   the classic *mutating-CSRF-via-`<img>`* class is closed. Both `Mutation` types are
   nonetheless live (`mutation { __typename }` → `200 Mutation`).
2. **Both Cosmo routers allow `GET` to execute queries; both Apollo servers block it.**
   Cosmo's `GET` surface is a *simple* request — reachable cross-site with no CORS
   preflight. The response is **not readable** (the gateway's `ACAO` allow-list is
   exactly `https://rivian.com`, §3), so there is no exfiltration. It becomes
   interesting only if a **side-effecting query** (not mutation) exists in the
   federated graph — the schema is closed, so that cannot be established. **Lead, not
   a finding.**
3. **The Cosmo routers disagree — and `rivian.com/api/gql/gateway/graphql` is the sole
   outlier, now at 5-vs-1.** With every endpoint enumerated, the *same* operation was
   sent to all five Cosmo routers:

   | Cosmo router | `GET ?query=mutation{…}` |
   | --- | --- |
   | `rivian.com/api/gql/gateway/graphql` | **`405` `INTERNAL_SERVER_ERROR`** ← **outlier** |
   | `business.rivian.com/api` | `405` *"Mutations can only be sent over HTTP POST"* |
   | `business.rivian.com/graphql` | `405` *"Mutations can only be sent over HTTP POST"* |
   | `api.rivian.com/graphql` | `405` *"Mutations can only be sent over HTTP POST"* |
   | `rivian.com/api/vs/gql-gateway` | `405` *"Mutations can only be sent over HTTP POST"* |

   **Five correct, one broken** — same product, same operation, same input. That is no
   longer a two-sample coincidence: that single deployment has drifted (version and/or
   configuration), and it is the one serving the public marketing site. On the gateway
   the "no mutating CSRF" property currently holds *by accident* — the request errors
   out — rather than by an explicit policy check. All five also disable introspection
   identically and enable APQ identically, which makes the `gateway`'s one divergence
   stand out further.

**RoE verdict: not reportable.** No sensitive information is disclosed by
`"Unexpected error occurred"`, and no impact is demonstrated — the RoE excludes
*"Verbose messages/files/directory listings without disclosing any sensitive
information"* (line 681). Recorded as hardening, plus a **configuration-drift lead**
worth confirming with the owner.

### 17. *informational* — anonymous schema reconstruction via error differential

Introspection is off (§1), but two of the four endpoints will confirm or deny any
field name one query at a time:

| Endpoint | Invalid-field response | Oracle? |
| --- | --- | --- |
| `orders` | `Cannot query field "X" on type "Query".` | **yes — precise** |
| `business/api` | `Cannot query field "X" on type "Query".` | **yes — precise** |
| `gateway` | `"Error in GraphQL validation"` (generic) | no |
| `content` | `"Invalid request."` (generic) | no |

A precise oracle is a schema-reconstruction primitive. **It was not used to
enumerate** — walking the field namespace one query at a time is exactly the
brute-force behaviour the RoE bans, and no schema was built. Recorded so a future
tester knows the primitive exists and that using it needs an explicit decision.

Confirmations actually obtained (low volume, single queries):

- **`me` exists on three of four** — `gateway` → `400 UNAUTHENTICATED`, `content` →
  `200` with `data.me = null`, `business/api` → **`401`**. Absent on `orders`.
- **`viewer` does not exist** on any endpoint.
- **`content` leaks a federated subgraph name:**
  `{"message":"User must be authenticated","path":["me"],"extensions":{"code":"UNAUTHORIZED","reason":"UNAUTHENTICATED","serviceName":"scheduler"}}`
  — i.e. `content`'s `me` resolver is served by a subgraph called **`scheduler`**.
  Minor federation-internals disclosure; informational.
- **`content` resolves authz per-field** (HTTP `200` + partial `data` + `errors`),
  whereas `business/api` rejects at the transport layer (HTTP `401`). Two different
  authorization postures worth knowing before writing any authn test.
- **No SDL leak:** `_service { sdl }` is rejected on all four, despite all four being
  federation-capable. A correct denial.

### 18. *informational* — APK-derived path inventory: `/mobile/*` are app-only deep links

The operator decompiled the in-scope Android app (`com.rivian.android.consumer`) and
supplied 19 paths. Sweeping them (`recon/apk-paths.txt`, `recon/apk-paths-enGB.txt`)
shows that **none of the interesting `mobile` routes are web-testable pre-auth** — on
the web they are all deep-link fallbacks:

| Path | Behaviour on the web |
| --- | --- |
| `/mobile/signin`, `/mobile/CustomerService` | `307` → **`/en-GB/download`** |
| `/mobile/VehicleService/{appointments,appointmentStatus,asyncMessages}` | `307` → `/en-GB/download` (query string preserved) |
| `/mobile/{vehicle-totp,vehicle-security,security-and-access}` | `307` → `/en-GB/download` |
| `/mobile/{upgradeToDigitalKey,keyfob2-activation,upgrades}` | `307` → `/en-GB/download` |
| `/mobile/rivian-assistant/google/enroll` | `307` → `/en-GB/download` |
| `/mobile/docs/guides/tire-change` | `307` → **`/en-GB/support/article/r1-tire-service-guide`** (a real article) |
| `/support`, `/support/digital-key-migration` | `307` → `/en-GB…`; the latter → `/en-GB` |
| `/en-GB/download` itself | `307` → `/en-GB` |

So `/mobile/*` is a **native-app routing namespace**, not a web surface: the security-
sensitive flows it names (TOTP, digital key, keyfob activation, vehicle security) are
reached from inside the app, not over these URLs. **No web-reachable surface here.**
Recorded so the list is not re-derived — and because the route *names* are useful
vocabulary for app-side testing later.

### 19. *informational* — `/mobile/static/` is a public, unauthenticated S3 asset namespace

`/mobile/static/<...>` bypasses the locale router entirely (no `307`) and is served
straight from **AmazonS3** through CloudFront — a separate origin behaviour from the
Next.js app. From the APK's own URL:

```
GET /mobile/static/whatsnew/722e16fd1249acf9/WhatsNew_2.5.0_en-US.mp4
-> 200  video/mp4  7,185,597 B  server: AmazonS3  x-amz-server-side-encryption: AES256
```

That is an **unauthenticated pull of app content** (release-notes video for app
v2.5.0). Bucket listing is **correctly denied**, which is the control that matters
here:

| Probe | Result |
| --- | --- |
| `/mobile/static/` | `200`, **0 bytes**, `Content-Type: application/x-directory`, `etag: "d41d8cd98f00b204e9800998ecf8427e"`, `last-modified: Fri, 07 May 2021` |
| `/mobile/static/whatsnew/` | `403` `<Error><Code>AccessDenied</Code></Error>` (`application/xml`) |
| `/mobile/static/whatsnew/722e16fd1249acf9/` | `403` `AccessDenied` |

Two readings, both recorded:

1. The `/mobile/static/` key is **not a live directory listing** — it is a **stored
   zero-byte S3 object** from May 2021 (the ETag `d41d8cd9…` is the MD5 of an empty
   body, and `application/x-directory` is object metadata). A "directory marker", not
   a directory.
2. **`ListBucket` is not public** — every prefix attempt returns S3 `AccessDenied`.
   Publishing static app assets anonymously is expected CDN behaviour, and
   **no sensitive content was observed**. Directory listings and S3 error verbosity
   are RoE-excluded anyway (*"Verbose messages/files/directory listings without
   disclosing any sensitive information"*, line 681). **No finding.**

The open question is whether **non-public** config lives in that namespace — app
update manifests, feature flags, or environment JSON. That is answerable from the
APK, not from guessing filenames (see *Next*).

### 20. *informational* — APK secrets triage: clean negative, and it is mostly scanner noise

The operator's `rivian-secrets.txt` (497 entries, from `base.apk`, app v3.16.0 /
versionCode 4897 / released 2026-09-03) was triaged. Full breakdown in
`recon/apk-secrets-triage.txt`. **Verdict: no valid secret.**

| Detector | Entries | Reality |
| --- | --- | --- |
| `[LinkFinder]` | 397 | URLs/paths — **noise for secrets, valuable for recon** |
| `[IP_Address]` | 71 | ASN.1 object identifiers (`0.100.1.1`, `1.2.156.1`, …) — **not IPs** |
| `[JSON_Web_Token]` | 21 | **zero** entries are JWT-shaped (no 3-segment ≥100-char value) |
| `[Authorization_Basic]` | 4 | Values are literal English prose — `"basic constraint"`, `"basic constraints."` |
| `[Generic_Secret]` | 1 | A 597-char **Stripe SDK class signature** (`"publishableKey"`, `"stripeAccountId"`) |
| `[Google_API_Key]` | **2** | real-shaped, 39 chars, `AIzaSy…` — see below |

**The two Google API keys are not submittable.** The RoE disqualifies them three
times, verbatim: *"Disclosed/misconfigured API keys (Maps, DD Monitoring, etc.)"*
(line 711), *"API key disclosure without proven business impact"* (675), and mobile
*"API key leakage used for insensitive activities/actions"* (750). No business impact
was proven and **no attempt was made to use them** — exercising a Google-hosted key
would send traffic to a third party, which the RoE puts out of scope. Recommendation
to the operator: **rotate/restrict, do not file.** (Note "DD" there means Datadog —
the same clause covers Datadog keys.)

Two further near-misses, both correctly *not* secrets: `assets/ds-test-ec.txt` and
`assets/ds-test-rsa.txt` are **Datadog SDK test fixtures holding public keys** (a
base64 DER EC P-256 SPKI and an RSA public key), and `assets/ds-{amex,cartesbancaires,
discover,mastercard,visa}.*` are Datadog's bundled **card-network root certificates**.

### 21. *informational (high-value lead)* — pre-release R2 features and an interior-camera stack

`assets/whatsnew.json` is the shipped "What's New" config. It gates **three
unreleased features** on a client-side flag set (`flags` + vehicle `firmwareFlags` +
`roles`):

| Page id | Flag | Firmware flag | Vehicle |
| --- | --- | --- | --- |
| `trip_companion_active_trip` | `activeTrip` | `ACTIVE_TRIP` | all |
| **`pet_cam`** | **`interiorCamera`** | **`INTERIOR_CAMERA`** | **R2** |
| `profile_pin` | `profilePin` | `PIN_PROFILE` | R2 |

Two observations, in order of importance:

1. **This is the strongest lead in the engagement.** `pet_cam` / `INTERIOR_CAMERA`
   is an **in-cabin interior camera** feature, and it pairs with the live-streaming
   stack found in the app source: `android/cloud/webrtc/` contains
   `GearGuardLiveStreamingService`, `KinesisVideoPeerConnection`,
   `SignalingServiceWebSocketClient`, `WebRtcManager` and `MediaDownloadManager` —
   i.e. **AWS Kinesis Video Streams over WebRTC with a WebSocket signalling channel**.
   The RoE's own top-priority scenario is *"Privacy invasion: Vulnerabilities that
   could allow unauthorized access to private user data stored in our systems"*
   (lines 622-624). The question worth the whole engagement is therefore
   **entitlement enforcement on remote camera/live-stream viewing** — can a
   non-entitled or cross-tenant session obtain a Kinesis signalling credential or
   view another vehicle's stream? That is **post-auth**, and it is where I would
   spend the credential budget first (*Not testable* §1).
2. **Feature gating is partly client-side.** `flags` are evaluated by the app; only
   the `firmwareFlags` actually bind in the vehicle. A client-side flag is not a
   security boundary on its own, but it does mean unshipped UI can be surfaced
   locally — and that the *entitlement* decision, if any, should be verified
   server-side. Recorded as a lead, not a finding: unlocking UI is not impact.

Also in `assets/whatsnewMock.json`: a **leftover mock fixture from production**,
containing an **internal Confluence URL**
(`rivianvwgroup.atlassian.net/wiki/spaces/rivcollab/pages/91907980/…`). It confirms
the §19 mp4 is mock data (`mediaFormat: "VIDEO"`, that exact URL) that was shipped to
production rather than stripped. An internal wiki pointer is **informational**, and
the host is third-party (Atlassian) so it is **out of scope to test**.

**RoE verdict: nothing reportable.** Product-roadmap disclosure and an internal URL
are not security vulnerabilities, and the RoE excludes *"Theoretical security issues
with no realistic exploit scenario"*. §20 is a proven negative; §21 is intelligence
that should steer the next phase, not a submission.

### 22. *informational* — the APK DEX exposes two more GraphQL gateways that probing could not find

Extracting strings from `classes*.dex` (145 distinct URLs) recovered the **endpoint
layer that the obfuscated Java and `robots.txt` had both hidden**. Three in-scope
discoveries, all of them **new** — none appears in any prior sweep of this engagement:

| Endpoint | What it is |
| --- | --- |
| `https://api.rivian.com/graphql` | **Cosmo Router** — live. `api.rivian.com/` returned `404` at root and was written off in *Not testable* §4; the endpoint was one path away the whole time |
| `https://rivian.com/api/vs/gql-gateway` | **Cosmo Router** — "vs" ≈ vehicle services. Absent from `robots.txt` and from the Next.js bundles |
| `wss://api.rivian.com/gql-consumer-subscriptions/graphql` | **GraphQL-over-WebSocket subscriptions** — the app's realtime channel (§23) |

Both new gateways behave exactly like `business/api`: `POST { __typename }` → `200`,
`mutation { __typename }` → `200 Mutation`, `GET` queries execute, mutations over
`GET` correctly `405`, field oracle precise, `_service { sdl }` refused, `me` absent.
**That brings the known GraphQL surface to six HTTP endpoints plus one WebSocket**, and
it retires a wrong conclusion from *Not testable* §4 — the DEX is a better enumerator
than path guessing.

Also recovered: **`https://rivian.com/account/handoff` → `308` → `/en-GB/auth/handoff`**
(`200`, the `/auth` app). It issues `_csrfSecret` / `_csrfToken` (double-submit CSRF)
and `riv-ld-context-v3` — a base64 JSON **feature-flag context**
(`{"kind":"user","deviceType":"desktop","location":{"country":"GB","state":"WLS"}}`),
i.e. a **LaunchDarkly-style client flag context**. Informational; the flag key is a
client-generated UUID, not a secret.

**New out-of-scope domain recovered — treat exactly like `goriv.co`:**

```
https://api.rivianservices.com/tiling/mobile_style.json   (+3 style variants)
```

`rivianservices.com` is **not** `rivian.com` and **not** `*.rivian.com`, so it is
**outside the RoE**. The app uses it for map tiles. **Never resolved, never touched.**

The DEX also confirms the live-streaming architecture in §21 (`data.iot.<region>.amazonaws.com`
for MQTT-over-WSS, i.e. the app talks **directly to AWS IoT**) and shows **Play
Integrity** is bundled — though **no evidence the app enforces the integrity verdict**.

### 23. *hardening* — the subscription WebSocket is correctly gated (clean negative)

The WebSocket endpoint accepts an **unauthenticated upgrade** (`HTTP 101`) — which
looks alarming and is normal for WebSocket. The security-relevant question is what
happens at the GraphQL layer, so a single `connection_init` was sent with an **empty
payload** (no token), once per subprotocol:

| Subprotocol | Result |
| --- | --- |
| `graphql-transport-ws` | `101` upgrade **accepted**, then **closed `4400 Bad request`** on `connection_init` |
| `graphql-ws` (legacy) | **`426 Upgrade Required`** — rejected |
| *(none)* | **`426 Upgrade Required`** — rejected |

So the realtime surface is properly controlled: it requires the modern subprotocol
**and** rejects unauthenticated initialisation. The `101` is therefore **not** a
missing-auth finding. Recorded because the `101` alone would otherwise read as one —
and because the *same* socket is the channel most likely to carry live vehicle state,
making it the natural place to retest **once authenticated** (*Next*).

**Method note:** one connection per subprotocol, two frames total, no subscription
loop and no load. The read-only `subscription { __typename }` was only reached on the
transport that had already rejected `connection_init`, so no subscription was ever
established.

### 24. *informational* — Basecamp's auth architecture, and two more in-scope hosts

The operator's authenticated capture put the whole Basecamp login flow on disk. Its
bundle (`recon/login-basecamp-bundle.js`) yields the real auth design — and **two new
in-scope hosts** that neither CT nor path probing had surfaced:

| New host | Role |
| --- | --- |
| `login.basecamp.rivian.com` | **"Basecamp Sign In"** — Vite SPA, `noindex,nofollow`. Not in CT, not in the asset list |
| `commauth.basecamp.rivian.com` | **AWS API Gateway** custom domain fronting the auth REST API (`/prod`); `403 {"message":"Missing Authentication Token"}` on unmatched routes |

The auth design (`recon/basecamp-authflow.txt`):

```
cognitoDomain  basecamp-prod.auth.us-east-2.amazoncognito.com
userPoolId     us-east-2_v9tkodinG
clientId       9plgmlt04deagrmevuict1u7l
authRestApi    https://commauth.basecamp.rivian.com/prod
scopes         openid email profile aws.cognito.signin.user.admin
flow           OAuth2 authorization_code + PKCE (S256), state checked on return
cookieDomain   basecamp.rivian.com        mfaSetupEnabled  true
```

**The flow itself is built correctly**: Authorization Code **with PKCE**, `state`
validated against storage (`mismatch` / `missing_stored` / `missing_returned` paths
exist), codes exchanged at `oauth2/token`, refresh via `refresh_token`. `clientId` and
`userPoolId` are SPA-embedded and therefore **public by design** — not secrets.

Two things in that config are *not* correct-by-default, and they are split out below.
The third is benign but worth stating: **`cookieDomain: 'basecamp.rivian.com'`** means
the auth tokens are scoped to `*.basecamp.rivian.com` — which includes
**`legacy.basecamp.rivian.com`** (the component-library remote, §13) and
`procurement.basecamp.rivian.com`. The partner-portal session therefore spans every
`basecamp` subdomain, not just the sign-in host. Informational on its own; it matters
only if any of those siblings is less trusted.

### 25. *hardening (strongest finding candidate)* — `goriv.co` is trusted by two separate auth mechanisms

The post-login return allowlist is a **suffix** list, not a host list:

```js
allowedReturnHostSuffixes: ['basecamp.rivian.com','rivian.com','scm.goriv.co','goriv.co']
```

and it is applied as `r === s || r.endsWith('.' + s)` — so **every** host under each
suffix qualifies. `goriv.co` is **not a Rivian-branded domain**, it is a **sibling
registrable domain**, and the RoE does not include it (§ *Scope trap*).

This is now the **second** independent auth control that trusts `goriv.co`:

| # | Mechanism | Evidence | Trust placed in `goriv.co` |
| --- | --- | --- | --- |
| §14 | Fleet portal (`business.rivian.com`) session cookie | `Set-Cookie: session…; Domain=.goriv.co` | session namespace shared with the sibling domain |
| §25 | Basecamp partner-portal post-login redirect | `allowedReturnHostSuffixes` includes `goriv.co`, `scm.goriv.co` | post-authentication navigation may be sent to any `*.goriv.co` host |

Two unrelated systems trusting the same out-of-scope domain is not a coincidence — it
looks like org-wide config that predates (or ignores) a domain split. Consequence: **if
any `*.goriv.co` host is attacker-influenced or dangling, both the Fleet session
namespace and the partner portal's post-login redirect are exposed.** The
post-login-redirect case is the worse of the two, because an open redirect immediately
after authentication is a phishing primitive against partner users, and it carries a
URL that a partner may already trust.

**Why this is not filed as a vulnerability yet — stated plainly:** the exploit needs a
`*.goriv.co` host under attacker control. **`goriv.co` is out of scope, so that
precondition was never tested**, and the redirect itself is client-side (the allowlist
lives in JS), so it cannot be demonstrated with `curl` at all — it needs a browser.
This is a **well-evidenced misconfiguration with an untested precondition**, which is a
legitimate hardening report, not a proven exploit. See *Next*.

### 26. *hardening* — the partner auth REST API exposes unauthenticated recovery routes, inconsistently

Three routes were recovered **from the bundle** (client-derived, not wordlisted) and
each was exercised once, with **only the operator's own throwaway address** — never a
third party's (`recon/basecamp-authrestapi.txt`):

| Route | Result | Reading |
| --- | --- | --- |
| `POST /prod/resetmfaemail` `{email}` | **`404 "User not found"`** | **account-existence oracle** |
| `POST /prod/resendrstpwdemail` `{email}` | `200`, empty body | **enumeration-resistant** |
| `POST /prod/resetmfaverify` `{token}` | `400 "Invalid token"` | correctly rejects bad tokens |

Three observations, in order of value:

1. **The inconsistency is the finding.** `resendrstpwdemail` deliberately returns `200`
   for a non-existent account — the correct enumeration-resistant pattern.
   `resetmfaemail`, its sibling in the same API, returns **`404 "User not found"`** and
   breaks it. One of the two is wrong, and the fix is trivial. The RoE excludes
   *"Username enumeration"* (line 685) from bounty, so this is **hardening, not
   reportable** — but it is concrete, evidenced, and actionable.
2. **An MFA reset can be *initiated* by an unauthenticated caller.** `resetmfaemail`
   needs no session — only an email address. The security of the reset then rests
   entirely on the emailed token, which was **not** tested: exercising valid tokens
   would be brute force, which the RoE bans. So: the *initiation* is unauthenticated by
   design (common for email-based recovery), and whether that design is *safe* is
   **unproven and must not be overclaimed**.
3. `resendrstpwdemail` is an **unauthenticated arbitrary-address mail-send primitive**.
   The RoE excludes *"Email bombing"* explicitly (line 699), so this is recorded, not
   filed.

`resetmfaverify` rejecting a garbage token (`400 Invalid token`) is a **clean
negative** — there is no empty-token or obvious-prefix bypass.

### 27. *informational (architectural)* — Fleet and the partner portal share one identity plane; the basecamp "authentication bypass" scope is closed

The operator authorised a single live login attempt, so `/oauth2/authorize` was
requested against the Basecamp Cognito pool. **It never offered a credential form.**
Cognito answered `302` straight to Microsoft:

```
GET https://basecamp-prod.auth.us-east-2.amazoncognito.com/oauth2/authorize
  response_type=code&client_id=9plgmlt04deagrmevuict1u7l
  &redirect_uri=https://login.basecamp.rivian.com/landing&code_challenge_method=S256
-> 302  https://login.microsoftonline.com/f798cb4f-b8b7-45f7-ad25-1ff5f130070a/oauth2/v2.0/authorize
          ?client_id=622bb053-2aa1-45d2-a10b-828f03c21aac
          &redirect_uri=https://basecamp-prod.auth.us-east-2.amazoncognito.com/oauth2/idpresponse
          &scope=profile email openid
```

**The tenant in that redirect is `f798cb4f-b8b7-45f7-ad25-1ff5f130070a` — the same
Entra ID tenant the Fleet portal uses** (§, `business.rivian.com` bundle). Two
consequences:

1. **The basecamp authentication-bypass scope is closed, and closed correctly.**
   Basecamp has **no password form at all** — it federates to Entra ID immediately.
   The consumer identity (Rivian's own Cognito pool, password + reCAPTCHA + OTP) is
   simply not a Basecamp credential, and neither is any other pre-auth primitive on
   that host. **No bypass, and not for want of looking:** the design removes the
   password-based attack surface entirely, which is the right answer to the RoE's own
   *"scope of testing for this domain is authentication bypass"* — there is no
   pre-auth credential path to attack. An external researcher would need a
   **partner-federated Entra identity** to go further, which the RoE says is not
   provided.
2. **Fleet and the partner portal are one trust domain.** Three identity planes exist,
   and only two are distinct:

   | Surface | Identity |
   | --- | --- |
   | consumer — `rivian.com`, `rivian.com/auth` | Rivian's own Cognito pool: password + reCAPTCHA Enterprise + OTP/MFA |
   | **Fleet** — `business.rivian.com` | **Entra ID `f798cb4f-…`** (MSAL) |
   | **Partner — `basecamp.rivian.com`** | Cognito pool `us-east-2_v9tkodinG` **→ federates to Entra ID `f798cb4f-…`** |

   This **reframes §25**. The shared `goriv.co` trust is not two unrelated
   coincidences: Fleet and Basecamp are the *same* identity plane, and that plane
   trusts `goriv.co` in two places. It also explains why the two share a
   person-shaped user model. For the program this is worth stating plainly: **a single
   Entra tenant is the gate for both partner and Fleet access, so the blast radius of
   an Entra-side compromise is both portals, not one.**

**No credential was transmitted.** The flow terminated at the federated IdP redirect,
before any credential form was reached, and the redirect was **not followed** into
Microsoft. Recorded in `recon/basecamp-cognito-login.txt`; no password, code or token
value is stored anywhere.

### 28. *informational* — the authenticated operation set dwarfs what introspection showed, and the CMS preview flag is correctly locked

The capture held **32 authenticated GraphQL requests** across **7 distinct operations**
— four of which nothing else in this engagement revealed. This is the concrete answer
to *"does GraphQL change for authenticated accounts?"*, with the negatives marked:

| Operation | Endpoint | Notes |
| --- | --- | --- |
| `getChatCategories` / `getChatCategoryAvailability` | `content` | support-chat config; **identical unauthenticated** (public by design) |
| `mutation CreateCsrfToken` | `orders` | mints a token; **works unauthenticated** — expected, it is needed pre-login |
| `query getUserDetails { user { firstName lastName email … **phone { countryCode number formatted }** **address { postalCode }** } }` | `orders` | **richer PII than the variant found earlier.** Replayed unauthenticated → `CSRF_TOKEN_EXPIRED`, `data: null`. **No leak.** |
| `query RelatedArticles($categorySlug,$locale,**$preview**)` | `content` | **Contentful** knowledge-base query |
| `query EgFormSection($entryId,$locale,**$preview**)` | `content` | Contentful **fetch-by-entry-id** query |
| `mutation contactAttrCapture($contactAttr)` | `content` | lead capture; returns `success`, `isNewContact`, `gtmEventId` |
| *(1 `gateway` op, empty operation name)* | `gateway` | did not parse cleanly |

**The one genuinely promising lead in that set — and the honest reading is worse than "locked".**
Both Contentful queries carry a **`$preview: Boolean`**, which is exactly where CMS
integrations leak unpublished drafts. My **first** attempt at this was methodologically
bad and was caught by the operator: I used *guessed* variables
(`categorySlug:"vehicle-registration"`, `entryId:"tell-us-more-contact-info"`), which
returned empty/`null` — a **broken baseline cannot support a conclusion**. The capture
shows the app's real variables and, importantly, that the app **never sends `preview` at
all**:

```
RelatedArticles  {"locale":"en-US","categorySlug":"registration-and-fees"}
EgFormSection    {"entryId":"1WFBjmjn2IHLT07sXQ9USO","locale":"en-US"}   <- a Contentful ENTRY ID
```

Re-run with those exact values as a **positive control**
(`recon/contentful-preview-retest.txt`):

| Probe | `RelatedArticles` | `EgFormSection` |
| --- | --- | --- |
| exact app vars (no `preview` key) | real data, 953 B | real data |
| `preview: false` | **identical**, 953 B | **identical** |
| `preview: true` | Contentful `ACCESS_TOKEN_INVALID` | Contentful `ACCESS_TOKEN_INVALID` |

The controls now pass, so flipping **one boolean** is a valid experiment — and the result
is **not** a hardened control:

- The `preview` argument is **accepted by the schema and reaches the resolver** — its
  value *changes server behaviour*. It is not ignored.
- `preview: true` makes the server **attempt a Contentful Preview API call**, and that
  call is rejected because the **preview token is invalid/unprovisioned**.
- So the correct description is **a latent exposure, not a locked door**: the
  draft-content code path is reachable by unauthenticated callers and currently errors
  out only because a token is broken. **Provision or rotate that token and anonymous
  draft disclosure appears** — no other change required.

That reframing is the finding: a public GraphQL endpoint should not expose a `preview`
argument at all, or should gate it behind authentication/authorisation, rather than rely
on an invalid token as the control. No draft content leaks **today** (`data` is absent on
the error). It also confirms the backend is Contentful beyond doubt — the error extension
names it.

**A related hypothesis worth testing with a session:** if the resolver selects the
preview token based on the *caller's* context, then `preview: true` may succeed for an
authenticated staff/editor identity — which would make this a draft-access vector rather
than a dead end. That ties this finding to the introspection question below, and both
need one fresh session to settle.

**What the capture does *not* answer.** It contains **zero introspection attempts** —
the app never sends one, authenticated or not. So *"is introspection enabled for
authenticated users?"* is **not answerable from the capture**; it needs a live
authenticated request (fresh session, *Next*). The prior expectation is *no* — Apollo
Server and Cosmo Router disable introspection by server configuration, not by identity,
and all seven endpoints already refuse it unauthenticated — but that is an expectation,
not a measurement, and is recorded as such.

**Also learned: the `/auth` app is not REST.** `POST /auth/{login,forgot,reset}` are
**Next.js Server Actions** — a `Next-Action: <40-hex>` header with a `text/plain` array
body, content-type deliberately simple. That matters because simple-typed POSTs are
cross-site reachable **without** a CORS preflight, so the control that must hold is an
Origin or token check. It was tested (`recon/nextjs-serveraction-origin.txt`): **every
Origin — `rivian.com`, `evil.example`, `null`, and absent — returns the identical
`403 Invalid csrf token`.** The **application-level CSRF token fires first and rejects
forged requests**, which is a *stronger* control than the framework Origin check would
be. No login-CSRF or reset-CSRF finding. (An earlier draft of that evidence file
guessed the opposite from the identical responses — corrected in place, since identical
output here means the CSRF check *dominated*, not that Origin is unchecked.)

> **Operational note.** While extracting the Server Action bodies, one print slice
> (120 chars) happened to include the account password in cleartext in this session's
> transcript. It is a throwaway account, nothing was written to disk or to any tracked
> file, and no credential value appears anywhere in `recon/` or the README — but the
> password is now in session history and should be treated as burnt.

### 29. *finding* — `contactAttrCapture` is an anonymous CRM/identity write accepting third-party marketing + SMS consent

This is the first item in this engagement that meets the *finding* bar rather than
hardening. Discovered in the capture, then tested with deliberately **non-routable**
data (`example.com` is IANA-reserved and cannot receive mail; `+15555550100` is the
reserved fictional range), so no third party could be contacted
(`recon/contactattrcapture-probe.txt`).

```
POST /api/gql/content/graphql          # NO cookies, NO session, NO Csrf-Token header
mutation contactAttrCapture($contactAttr: ContactAttrInput!) {
  contactAttrCapture(contactAttr: $contactAttr) { success isNewContact gtmEventId }
}
variables.contactAttr:
  email: "probe-test@example.com", phone: "+15555550100", first/last/postal_code: arbitrary,
  subscribe_to_marketing: true, sms_notification: true,
  product_interests: ["r2"], create_source: "web-tell-us-rsvp"
-> 200  {"data":{"contactAttrCapture":{"success":true,"isNewContact":false, ...}}}
```

**What is proven:**

1. **The mutation executes fully unauthenticated, with no session and no CSRF token.**
   An `application/json` POST is a *non-simple* request, so Apollo's CSRF prevention —
   which correctly blocks `GET`/simple requests on this same endpoint (§2) — does not
   apply. Nothing else gates it.
2. **The payload carries consent flags** (`subscribe_to_marketing`,
   `sms_notification`) alongside **arbitrary, unverified** email/phone/name/postal-code.
   The server neither verifies ownership of those details nor requires any session.
3. **`success: true`** is returned for an anonymous caller.
4. Against the RoE's *"Cross-site Request Forgery"* exclusion this is **not** CSRF — no
   cross-site vector is needed; it is a **direct, unauthenticated write primitive**.

**What is NOT proven — stated plainly, because it bounds the finding:**

- **Record creation is unconfirmed.** `isNewContact` returned **`false`** on every call,
  *including the first call for a fresh address*, and `gtmEventId` was **identical**
  across repeats (a deterministic hash of the input). So either the downstream upserts
  idempotently, or my very first attempt already created the record and subsequent calls
  report "not new" — I cannot distinguish these from outside.
- **Reliability is poor.** The same request intermittently returned
  `ERROR_UNABLE_TO_CREATE_IDMS_USER` / `DOWNSTREAM_SERVICE_ERROR`; the internal service
  behind it appears flaky. **So the abuse cannot be scaled/predicted from here.**
- **Consequence:** the *access-control* defect is solid and demonstrable — an anonymous
  caller reaches a CRM/identity write and receives `success: true`. The *impact*
  (mass third-party enrolment) is **inferred, not demonstrated**.

> **Self-correction.** An intermediate version of this probe concluded that the CSRF
> token was the gate, because a no-token call failed once. Repeating it showed the
> no-token call **succeeding**, so that failure was transient and the conclusion was
> wrong. The token is **not** a control here; the earlier contrast was an artefact of
> flakiness.

**RoE filter — the honest read.** Not clearly excluded: the OOS list covers
*"Cross-site Request Forgery with no or low impact"* (this is not CSRF and the impact is
not low if enrolment works), *"Email bombing"* (this is persistent consent enrolment
rather than a mail flood, though a triager may reach for that clause), and *"Spam"*
(that clause addresses researcher conduct). The strongest framing for a report is:
**an unauthenticated endpoint that accepts arbitrary third-party contact details
together with marketing and SMS consent flags, and writes them into Rivian's
identity/CRM downstream** — i.e. a business-logic/access-control defect with a
compliance dimension (TCPA/PECR-style unsolicited SMS), not a mail-flood.

**Recommendation:** worth filing, with the impact caveat stated up front rather than
buried. Pair it with §25 (`goriv.co` trust) as the two submission candidates.

---

### 30. *informational* — the Contentful `entryId` is a random ID, the resolver type-filters, but public queries leak IDs

Prompted by a specific question: *is `entryId` a hash/base64, does it relate to the
category, and could new ones be found to reach content the browser flow never
exposes — do they assume the ID is a control?* Answered with evidence
(`recon/contentful-idprobe.txt`):

1. **It is not a hash and not derived from the slug.** `1WFBjmjn2IHLT07sXQ9USO` is
   exactly **22 characters** of `[A-Za-z0-9_-]` — Contentful's standard nanoid-style
   entry-ID shape. It decodes as base64 only coincidentally (22 chars ≈ 16 bytes); it
   is **not** a digest of `tell-us-more-contact-info`, and it is **not** reversible.
2. **The relationship is a *reference*, not a derivation.** The capture shows a parent
   entry holding it:
   `"formSectionsCollection":{"items":[{"sys":{"id":"1WFBjmjn2IHLT07sXQ9USO"},"slug":"tell-us-more-contact-info"}]}`
   — i.e. the parent points at the child by `sys.id`. That is the mechanism by which
   IDs are discovered at all: **graph traversal, not guessing**.
3. **"They assume it's a control" — refuted.** Valid Contentful IDs harvested from the
   capture (`64fV9OQvMJKrw4KkM45HEH`, `1qG3F38CwX255uu2oSU2L0`, `3Dp2LCVQOabvN47WrtDo7Z`,
   `2ncCVeHAmMSK4GAFX9SH3X`) were passed to `egFormSection(id:)` and **every one
   returned `null`**, while the genuine form ID returned the form. The resolver
   **filters by content type**, so an ID is not a capability and knowing an ID of the
   wrong type grants nothing. That is an actual control, not an assumption.
4. **IDs *are* harvestable — but only for already-public content.** `sys { id }` is
   exposed on public collection queries, so adding it to `RelatedArticles` yields
   category and article IDs (`7FXawdZPOYdKeDSaxrlt06`, `2JV3sfOebno6z9SNFpXpju`) that
   the browser flow never shows. This walks the CMS graph from published roots. It
   **cannot** reach unpublished content: that path needs `preview: true`, and the
   preview token is invalid (§28).

So the net is a **negative with a usable recon technique attached**: IDs are random and
type-gated, so they are not an access-control façade; `sys { id }` is nonetheless a
legitimate way to enumerate *published* CMS structure. Worth knowing before anyone
spends time on ID guessing, which cannot work.

### 31. *informational* — full response-body review: new routes, a nav-level scope trap, and a leaky route manifest

Every distinct response body in the capture was reviewed
(`recon/newroutes.txt`, 50 distinct request/response pairs). Results:

**1. A scope trap inside Rivian's own navigation.** The nav config in the page props
links `/gear-shop` and `/gear-shop/c/{wheels-and-tires,adventure-gear,charging}` — and:

```
GET /gear-shop  -> 301  https://gearshop.rivian.com
```

`gearshop.rivian.com` is an **explicit RoE carve-out** (§ *Scope trap*, "Out of scope").
So **following the site's own menu leads a tester out of scope**, with no marker that it
has done so. Recorded because that is exactly how an engagement goes wrong: the
navigation is trusted, and the destination is a carve-out. Never followed.

**2. New public routes recovered from the page props** (route inventory the browser flow
never displayed). `/r3` was fetched to confirm it is real:

| Route | Result |
| --- | --- |
| `/r3` | **`200`, 188,877 B — "Rivian R3: Electric Crossover"** (the page is live) |
| `/configurations/builder/r2` | **`200`, 292,506 B — "Design Your Rivian R2 \| Configurator"** |
| `/en-GB/{autonomy,connect-plus,technology,spaces}` | `200` — real pages |
| `/demo-drive/book`, `/trade-in/vehicle-info`, `/offers`, `/compare`, `/fleet`, `/experience/*`, `/support/*` | published routes from the nav config |

These are **published marketing/configurator pages**, so their existence is **by design**
and not a disclosure finding — but they are **new surface** (a live R2 configurator, a
demo-drive booking flow, a trade-in form) that no prior sweep in this engagement reached.
Unreleased-model material also ships in the payloads (`R2_Cover_Image_No_Date.jpg`,
`/r3` in nav).

**3. A locale-router defect.** `/en-GB/gear-shop` returns
`307 -> /en-GB/en-GB` — a **malformed double-prefix** rather than the intended external
redirect. Harmless in impact, but it is a genuine routing bug on an in-scope host.

**4. The RSC flight payloads leak the internal route tree.** The 43 KB "JSON" bodies are
**Next.js flight streams**, not JSON, and they carry the framework's route manifest —
including **route groups that never appear in a URL**:

```
"siblings":["_not-found","_global-error","account","favicon.ico"]
"name":"(authed)"   "name":"(nav)"   "name":"settings"   "name":"personal-information"
```

So `/account`'s post-auth structure (`(authed)/(nav)/settings/personal-information`) is
disclosed by the flight payload of an unauthenticated page load. That is a
**client-derived route-enumeration technique** — fetch a page, read its manifest — and it
is strictly better than a wordlist, which the RoE bans. The tree recovered here is small
because the capture only covered a few pages; a full walk would need one request per page
and a session for the authed segments.

**5. `/context/extension`** is a leftover route that meta-refreshes to `/en-GB`
(`<meta id="__next-page-redirect" http-equiv="refresh" content="1;url=/en-GB"/>`), served
from the `/root` chunk set. Informational.

**6. Clean negatives from the same pass.** No Contentful **delivery/preview token**
appears in any body or fetched bundle (the apparent hits were article slugs and MSAL
internals, not tokens); **no new `rivian.com` subdomain** beyond the known ones; **no
`goriv.co` or `rivianservices.com` reference in any HTTP body** (both appear only in
client bundles); no AWS keys, ARNs or S3 bucket URLs; no internal/staging endpoints.
`LDClient` appears in bodies, consistent with the LaunchDarkly context cookie (§22).

### 32. *finding (best candidate)* — the Tier-1 Fleet API discloses internal service topology to unauthenticated callers

The Fleet login bundle contains the Fleet auth GraphQL operations (recovered with
`recon/fleet-authops.txt`). Replaying them unauthenticated against
**`business.rivian.com/api`** (Tier-1) shows the auth gates hold — but the **error
handling leaks internal infrastructure**:

| Operation | Unauthenticated result |
| --- | --- |
| `query getUserRole { currentUserRoles }` | `401 Not authenticated` ✓ |
| `mutation logout` | `401 Not authenticated` ✓ |
| `mutation businessLogin($u,$p)` | `Invalid credentials.` (generic — no enumeration) ✓ |
| `mutation ssoExchange($ssoToken)` | **proxied to an internal service; internal response reflected** ✗ |

`ssoExchange` with any ≥100-char non-valid token returns:

```json
{"errors":[{"message":"500: Internal Server Error","path":["ssoExchange"],
  "extensions":{"code":"INTERNAL_SERVER_ERROR",
    "response":{"url":"http://et-service-bastion.et-service-bastion/v1/sessions",
                "status":500,"statusText":"Internal Server Error",
                "body":{"message":"Internal Server Error"}},
    "target":"BASTION_ERROR","reason":"REST_DATA_SOURCE_ERROR",
    "serviceName":"dt-gql-auth"}}],"data":null}
```

What an **unauthenticated** caller learns from a Tier-1 host:

- **An internal hostname and API path**: `et-service-bastion.et-service-bastion` /
  `/v1/sessions` — a Kubernetes-style `<service>.<namespace>` name, i.e. an
  **internal-only service** that is not otherwise reachable.
- **The internal scheme is plain `http://`** — not TLS, inside the trust boundary.
- **Internal service/subgraph names**: `dt-gql-auth`, and from
  `accountSetProvisionalUserPassword`, **`dt-gql-account-manager`**.
- **Internal error taxonomy**: `BASTION_ERROR`, `REST_DATA_SOURCE_ERROR`.
- **Confirmation that a caller-controlled value is proxied to that internal service** —
  a server-side request whose destination is fixed but whose token is attacker-supplied.

**Token validation itself is sound** (tested and negative): a forged `alg:none` JWT and
an `HS256` JWT signed with a guessed key both returned `Invalid credentials.`, so there is
**no signature bypass** — the JWT path is validated locally and rejects properly. The
disclosure is purely the **bastion error path**.

**Honest severity: Low, possibly Medium ($100–700).** The RoE gate to watch is
*"Verbose messages/files/directory listings without disclosing any sensitive
information"* (line 681) — a triager could dismiss this as error verbosity. The
counter-argument, and the framing I would use: the leaked material is **internal
topology an external attacker is not meant to see** (an internal service name and path,
plus a plain-HTTP internal URL), it comes from a **Tier-1** host whose declared scope is
*authentication/authorization of publicly available endpoints*, and it reveals an
unauthenticated **server-side request into an internal service**. No data compromise is
demonstrated, so this should be filed as information disclosure with an honest impact
statement — **not** dressed up as SSRF or RCE.

Also worth noting from the same bundle: `AccountResetPassword` takes
`{resetCode, password}` and `accountSetProvisionalUserPassword` is reachable
unauthenticated on the account-manager subgraph. **Neither was tested further**: probing
reset codes or hunting input field names by trial is enumeration/brute force, which the
RoE bans. Recorded as **untested**, not as findings.

### 33. *informational* — the consumer app's 178 GraphQL operations, and the gating that closes them

Extracting GraphQL documents from the consumer APK gave the **full client operation
inventory: 178 distinct operations** (`recon/consumer-ops-gateways.txt`). It is the
richest surface map in this engagement, and it named the operations that matter for the
RoE's stated worst cases:

| Class | Examples |
| --- | --- |
| **Remote vehicle control** | `SendRemoteCommand($vehicleId,$model,$parallaxPayloadB64)` → `sendParallaxPayload`; `SendVehicleOperation($vehicleId,$payload)`; `departNow`; `ParseAndShareLocationToVehicle($vehicleId)` |
| **Vehicle security** | `SetUserPin($pin)`, `DeleteUserPin`, `SetPinAuth`, `enableKey($keyIdentityId,$HRID)` / `disableKey`, `CreateSigningChallenge` / `VerifySigningChallenge` (digital-key attestation) |
| **Access management** | `RemoveUserFromVehicle`, `RescindInvitations($guestIdList)`, `SendAsyncMessage` |
| **Privacy / cameras** | `liveNotificationRegisterStartToken($deviceId,…)`, `GetPrivacyPreferences($vehicleId)`, `setLocationSharingConsent` |
| **Money** | `createPaymentMethod`, `deletePaymentMethod($paymentMethodId)`, `updateDefaultPaymentMethod`, `retryPayment($paymentReferenceId)`, `creditCheck` |
| **Account** | `Login`, `LoginWithOTP($email,$otpCode,$otpToken)`, `OAuthExchangeTokens`, `EnrollAuthenticatorMfa`, `updateUserPasswordWithOTP` |

Most carry **explicit object identifiers** (`vehicleId`, `addressId`, `paymentMethodId`,
`guestIdList`, `keyIdentityId`) — textbook BOLA candidates.

**They are correctly gated.** Attempting to invoke the highest-impact ones
unauthenticated against the Tier-1 gateway `rivian.com/api/gql/gateway/graphql`:

```
GetCurrentUserAddresses   -> 400 {"code":"UNAUTHENTICATED"} "User is unauthenticated"
GetUserPinExists          -> 400 UNAUTHENTICATED
GetVehicle                -> 400 UNAUTHENTICATED
VehiclesAndEnrollments    -> 400 UNAUTHENTICATED
```

The requests **pass field validation and are then refused at the authorization layer** —
which is the correct order and the correct outcome. So the consumer vehicle, key, PIN,
payment and address surface is **properly authenticated pre-session**, and the
BOLA hypothesis cannot be tested further without a session bound to a vehicle (which
*Not testable* explains is unavailable).

**The four operations most likely to pay were then tested specifically, and all are
gated** (`recon/consumer-highvalue.txt`) — this matters, because each is the kind of
thing that *would* have been a serious finding:

| Operation | Why it looked promising | Unauthenticated |
| --- | --- | --- |
| `vehicleOrders` | `orders(input:{orderTypes:[PRE_ORDER,VEHICLE], pageInfo:{from:0,size:10000}})` — client-controlled page size, up to 10 000 orders | **`UNAUTHENTICATED`** ✓ |
| `mediaUploadUrl($vehicleId,$fileName)` | mints a **presigned S3 upload URL** (`uploadUrl`, `s3Uri`, `expiresIn`) | **`UNAUTHENTICATED`** ✓ |
| `LogUploadURL($domain,$payload)` | **caller-controlled `domain`**, returns `postUrl`/`url` + signed `headers` — SSRF/credential-leak shape | **`UNAUTHENTICATED`** ✓ |
| `getPastInvoices($id)` → `queryByRivianId(id)` | returns `technicianAppointment.serviceAddress{ address1 city state postalCode country longitude latitude }` — **a customer's home address and GPS coordinates** | **`401 Not authenticated`** ✓ (on `/api/vs/gql-gateway`, where the field actually exists) |

The invoice one was tested with **the operator's own `rivianId`**, recovered from their
capture — never a third party's. Result: gated. So there is **no anonymous PII, order
or upload primitive** in the consumer API.

**Useful schema-routing fact recorded:** these consumer operations live on
**`rivian.com/api/gql/gateway/graphql`**, **not** on `api.rivian.com/graphql` (which
rejects `currentUser`/`getVehicle` outright) and not on `/api/vs/gql-gateway` (a
narrower schema — `ProvisionedUser`, `MfaEmailChannel`, `User`, `PrivacyConsentRecord`
are all absent). Sending an operation to the wrong gateway yields validation errors,
not authorization answers — a trap worth knowing before reading anything into a
"cannot query field" response.

---

## Tested and found clean (the bulk of the work)

Every row is a negative result with the control that produced it.

### Listed Tier-1 / Tier-2 assets

| Endpoint / asset | Probe | Result | Control that defends it |
| --- | --- | --- | --- |
| `rivian.com/` | `GET` | `307` → `/en-GB/` | CloudFront Function locale/geo router (`riv-detected-locale` cookie) |
| `rivian.com/api/gql/{gateway,content,orders}/graphql` | `GET`, no body | `400` (`GET query missing.` / Apollo CSRF block) | CSRF/preflight + method discipline |
| `rivian.com/api/gql/*` | single `{__typename}` | `200 {"data":{"__typename":"Query"}}` | — (confirms live, unauthenticated schema root only) |
| `rivian.com/api/gql/*` | introspection ×1 each | `400`, disabled | Apollo Server / Cosmo Router defaults |
| `rivian.com/api/gql/{gateway,orders}` | forged `Origin` ×3 | no `ACAO` | exact origin allow-list (positive control below) |
| `api.rivian.com/graphql` | `GET` / `POST {__typename}` | `400 empty request body` / `200 {"data":{"__typename":"Query"}}` | **new** — Cosmo Router found only via the APK |
| `rivian.com/api/vs/gql-gateway` | `GET` / `POST {__typename}` | same as above | **new** — Cosmo Router, absent from `robots.txt` |
| both new gateways | `POST { me { id } }` | `400 Cannot query field "me"` | `me` is **not** in these schemas — a different graph |
| both new gateways | `POST mutation {__typename}` | `200 Mutation` | Mutation types live |
| both new gateways | `GET ?query=mutation{…}` | `405 Mutations can only be sent over HTTP POST` | **correct** — unlike `gateway` (§16) |
| `rivian.com/en-GB/auth/handoff` | `GET` | `200`, 53 KB | `/auth` app; sets `_csrfSecret`/`_csrfToken` |
| `wss://api.rivian.com/gql-consumer-subscriptions/graphql` | `connection_init`, empty payload | **`4400 Bad request`** | auth enforced at init; legacy subprotocol `426` (§23) |
| `business.rivian.com/graphql`, `api.rivian.com/graphql`, `rivian.com/api/vs/gql-gateway` | introspection ×1 | `400`/`200`, disabled by Cosmo Router | consistent across all Cosmo routers |
| same three | `_service { sdl }` | `400 Cannot query field "_service"` | no SDL leak anywhere |
| same three | `GET ?query=mutation{…}` | **`405` correct** | 5-vs-1 — see §16 |
| **expired-session replay** | `/en-GB/consumer-ui/v1/user`, `{ me { id } }` ×2, `GetUserDetails` | `null` / `UNAUTHENTICATED` ×2 / `CSRF_TOKEN_EXPIRED` | **stale captured session correctly rejected by every entry point** |
| `content` `RelatedArticles` / `EgFormSection` | `preview: true` vs **positive control** | controls return real data; `preview:true` → Contentful `ACCESS_TOKEN_INVALID` | **latent exposure, not a hardened control** — the preview path is reachable unauthenticated and fails only on a broken token (§28) |
| `orders` rich `getUserDetails` (phone + address) | unauthenticated | `CSRF_TOKEN_EXPIRED`, `data: null` | no PII leak on the richer variant (§28) |
| `POST /auth/{login,forgot,reset}` (Next.js Server Actions) | forged `Origin` ×4 | identical `403 Invalid csrf token` | **app-level CSRF token dominates** — cross-site invocation blocked (§28) |
| `rivian.com/api/gql/nonexistent-9f3a` | `GET` | `404` (52,732 B site 404 page) | Next.js 404 |
| `rivian.com/api/gql/content/graphql/` **vs** `…/graphql` | `GET` both | **identical** `400`, 429 B, Apollo CSRF | trailing slash is routed identically — **no normalization differential** |
| `rivian.com/mobile/*`, `/support/*` (no locale) | `GET` | `307` → `/en-GB/<same>` | CloudFront Function locale router; see §18 |
| `rivian.com/mobile/static/…mp4` | `GET` | `200 video/mp4` from **S3** — no locale `307` | separate origin behaviour; see §19 |
| `rivian.com/mobile/static/whatsnew/{,<hash>/}` | `GET` | `403` S3 `AccessDenied` | **`ListBucket` not public** — listing correctly denied |
| `rivian.com/api/` | `GET` | `307` → `/en-GB/api/` | locale router |
| `rivian.com/auth/api` | `GET` | `404` | Next.js 404 — no JSON API behind the route |
| `rivian.com/quad/api` | `GET` | `404` | Next.js 404 |
| `rivian.com/account/api/`, `/demo-drive/api/`, `/experience/api/` | `GET` | `307` → `/en-GB/...` | locale router |
| `rivian.com/root/api` | `GET` | `200`, 177,194 B HTML — **catch-all** | `/root/zz-nonexistent-9f3a` also `200` (177,282 B) → wildcard route, not an API |
| `rivian.com/robots.txt` | `GET` | `200`, 375 B | intentional |
| `rivian.com/sitemap.xml` | `GET` | `200`, 1.12 MB, all `rivian.com` | locale + `/support`, `/newsroom`, `/investors` |
| `rivian.com/security.txt` | `GET` | `404` | absent |
| `rivian.com/.well-known/{security.txt,change-password}` | `GET` | `307` → `/404` | redirects to the site 404 |
| `business.rivian.com/` | `GET` | `302` → `/auth/?rd=…` | nginx auth gate |
| `business.rivian.com/auth/` | `GET`, with `rd=` variants | `200`, 400 B shell, **identical for all `rd` values** | `rd` is handled **client-side** — no server-side open redirect |
| `business.rivian.com/auth/?rd=https://example.com/` | `GET` | `200`, byte-identical shell | **no reflection** — redirect target never emitted by the server |
| `business.rivian.com/api` | `POST {__typename}` | `200 {"data":{"__typename":"Query"}}` | — |
| `business.rivian.com/api` | forged-origin `OPTIONS` | `403` | Cosmo Router origin/method policy |
| `business.rivian.com/token`, `/logout` | `GET` | `302` → `/auth/?rd=…` + `.goriv.co` cookie deletions | nginx auth gate; see §14 |
| `business.rivian.com/graphql` | `GET`, no body | `400 {"errors":[{"message":"empty request body"}]}` | second GraphQL server; see §15 |
| `business.rivian.com/api/v2/` | `GET` | `404` `404 page not found` (19 B) | Go service — distinct from `/api` |
| `business.rivian.com/auth` | `GET` | `200`, 400 B SPA + HAProxy `route` cookie | Vite SPA |
| `business.rivian.com/robots.txt` | `GET` | `302` nginx | nginx |
| `legacy.basecamp.rivian.com/remoteEntry.js` | `GET` | `200`, 15,466 B, JS | module-federation component library; see §13 |
| `basecamp.rivian.com/` | `GET` | `200`, 1,151 B SPA shell | S3 + CloudFront |
| `basecamp.rivian.com/{api/v2/,api/v2/health,zz-nonexistent-9f3a}` | `GET` | **`200` + identical 1,151 B shell** | SPA catch-all — status codes carry no signal for route discovery |
| `basecamp.rivian.com/asset-manifest.json` | `GET` | `200` + the same 1,151 B shell | no CRA chunk manifest is served — the app is a shell + the `legacy` remote |
| `basecamp.rivian.com/robots.txt` | `GET` | `200`, `Disallow:` (permissive) | intentional |
| `basecamp.rivian.com/manifest.json` | `GET` | `200`, 484 B | PWA manifest, no secrets |

### `*.rivian.com` wildcard — 33 in-scope hosts probed at root

Raw table: `recon/ct-http-fingerprint.tsv`. Nothing in scope returned an
unauthenticated content leak, and no takeover vector was found.

| Host | `HTTP` | Fronting / origin | Note |
| --- | --- | --- | --- |
| `www.rivian.com` | `308` | CloudFront | → `https://rivian.com/` (apex) |
| `api.rivian.com` | `404` | CloudFront → nginx | `x-riv-env: prod_ue1`, HSTS; no path enumeration |
| `api.stage.rivian.com` | `404` | CloudFront | staging twin |
| `api.dev.rivian.com` | `403` | CloudFront | denied at edge |
| `stage.rivian.com` | `403` | CloudFront | denied at edge |
| `prism.rivian.com` | `403` | CloudFront | denied at edge |
| `events.rivian.com` | `403` | Fastly + **DataDome** | bot management, not a bypass surface for this scope |
| `downloads.rivian.com` | `307` | CloudFront | → `/en-GB/` locale router |
| `images.rivian.com` | `307` | CloudFront (`dsbdwfyh3jpbu`) | → `/en-GB/` |
| `videos.rivian.com` | `307` | CloudFront (`dsbdwfyh3jpbu`) | → `/en-GB/` |
| `investors.rivian.com` | `301` | `awselb/2.0` | → `https://rivian.com/investors` |
| `supplierslogin.rivian.com` | `301` | `awselb/2.0` | → `https://basecamp.rivian.com/` (in scope) |
| `preorders.rivian.com` | `302` | CloudFront | → `https://rivian.com/configurator` |
| `tour.rivian.com` | `302` | CloudFront | → `https://rivian.com/careers` |
| `offlease.rivian.com` | `302`/`200` | — | → `/landing`, then `200 text/html` |
| `things.api.rivian.com` | `404` | **AWS API Gateway** | `application/json`; see §6 |
| `things.stage.rivian.com` | `404` | **AWS API Gateway** | `application/json` |
| `basecamp.rivian.com` | `200` | S3 + CloudFront | listed asset, see above |
| `gogoogle.rivian.com` | `200` | AmazonS3 | static stub → `riviancurrent.com`; see §4 |
| `googleguide.rivian.com` | `200` | AmazonS3 | static stub → `sites.google.com/rivian.com/guide`; see §4 |
| `link.rivian.com` | `404` | Fastly, `server: msys-et` | third-party email infra — see §7 |
| `go.rivian.com` | `404` | Fastly | email/short-link infra — not probed further |
| `cid`, `granite.p`, `limestone.p`, `ccc.api.dev`, `controller.ue1/uw2.prod`, `dashboard`, `em`, `things.dev`, `useast/uswest.guestlogin` | `000` | DNS resolves, **no listener** | see §5 |

### Explicitly *not* done, and why

| Considered | Decision |
| --- | --- |
| Port scan / `masprobe.py` (masscan + nmap) | **Not run.** Requires CIDRs; the RoE publishes none, and the targets resolve to CloudFront/EC2 edge addresses — scanning them would hit AWS infrastructure, not Rivian. |
| Path/directory brute force on `api.rivian.com`, `things.api.rivian.com`, `/api/v2/` | **Not run.** RoE bans brute force; root-level fingerprinting only. These remain leads, deliberately. |
| GraphQL alias overloading / depth probes | **Not run.** Named as a DoS vector in the RoE (line 722). |
| Credential brute force / credential stuffing | **Not run.** Banned; also no test accounts exist. |
| Open-redirect payload chains (`rd=` to attacker host) | **Only observed, never chained.** A benign `https://example.com/` and the in-scope host were compared; no payload chaining, no third-party redirect target touched. |
| The 8 carve-outs + `cloud.e.rivian.com` + `www.careers` + `staging-wpdg925-stories` + `goriv.co` | **Never resolved or fetched.** |
| 11 third-party SaaS hosts (Shopify, ExactTarget, Mailgun, Adobe, Google Sites, career.page, ldpgs, SparkPost) | **Never fetched.** Removed on CNAME evidence — see `recon/ct-thirdparty-excluded.txt`. |
| `legacy.basecamp.rivian.com` | **Not fetched.** Not in CT, not listed; held back. |

---

## Not testable / blocked

1. **The consumer surface is now reachable; the Fleet/partner planes are not.**
   The operator self-registered via the RoE's FAQ flow (lines 757-775) and supplied a
   session, so `rivian.com` account routes, `/consumer-ui/v1/user` and the
   authenticated GraphQL queries are all testable. What remains out of reach:
   - **`basecamp.rivian.com` — conclusively, and not for want of effort (§27).** There
     is no password form; Cognito federates straight to Entra ID tenant
     `f798cb4f-…`. An external researcher would need a **partner-federated Entra
     identity**, which the RoE states is not provided. **This area is closed.**
   - **`business.rivian.com` (Fleet)** — same Entra tenant, same obstacle.
   - **Every vehicle-bound flow** (digital key, keyfob activation, vehicle TOTP, Gear
     Guard live view, interior camera) — a fresh owner-registration has **no vehicle**
     attached, so these cannot be exercised at all. See *Next* — this needs the
     program owner, not more tooling.
2. **Schema-driven API mapping is impossible — but two endpoints leak field
   existence.** Introspection is disabled on all four GraphQL endpoints (§1), and no
   credentials or persisted queries are available. `orders` and `business/api` do
   return precise `Cannot query field …` errors (§17), which is a schema-oracle
   primitive; **it was not used to enumerate**, because walking a field namespace one
   query at a time is the brute-force behaviour the RoE bans. The only operations
   confirmed are `{ __typename }`, `mutation { __typename }`, and `{ me { id } }` on
   three of the four.
3. **`basecamp.rivian.com` route discovery is blind — and the bundles do not help.**
   The SPA returns `200` + an identical 1,151-byte shell for *every* path, so status
   codes cannot distinguish a real endpoint from a miss. Both fetchable JS artefacts
   were analysed and neither yields a business API: `main.js` is the shell + Datadog
   SDK (`/api/v2/{logs,rum,replay}` is Datadog's intake proxy, **not** a Rivian API),
   and `legacy.basecamp.rivian.com/remoteEntry.js` exposes only a design-system
   component library (§13). No CRA chunk manifest is served. There is therefore **no
   statically recoverable Basecamp API surface** — this needs a browser session or
   credentials, not more static analysis.
4. ~~**API path surfaces on `api.rivian.com` and `things.api.rivian.com` are unmapped.**~~
   **Partially superseded (§22).** Both hosts are live and in scope and returned `404`
   at root, which made them look unmappable without a wordlist. The APK DEX then
   handed over **`api.rivian.com/graphql`** and **`rivian.com/api/vs/gql-gateway`**
   for free. **`things.api.rivian.com` remains unmapped** (AWS API Gateway, root
   `404`) — the lesson is that a client artefact beats path guessing, not that the
   surface was unreachable.
5. **Mobile apps not tested.** `1570215232` (iOS) and `com.rivian.android.consumer`
   (Android) are in scope, but no APK/IPA was obtained or analysed this pass.
6. **11 DNS-only hosts unreachable.** `controller.ue1.prod`, `controller.uw2.prod`,
   `cid`, `granite.p`, `limestone.p`, `ccc.api.dev`, `dashboard`, `em`, `things.dev`
   do not answer on 443, and the two `guestlogin` records point at RFC 6598 CGNAT
   space. Nothing to test from the internet; the DNS records themselves are covered
   in §5.

---

## Reportability (RoE filter)

| Item | RoE verdict | Gate |
| --- | --- | --- |
| §1 introspection disabled | Control working — nothing to report | — |
| §2 Apollo CSRF preflight | Control working — nothing to report | — |
| §3 CORS allow-list exact | Control working — nothing to report | — |
| §4 stub hosts → non-`rivian.com` domain | **Not reportable** — targets verified Rivian-owned | *"Subdomain takeover"* (line 706); no takeover exists |
| §5 internal hostnames in public DNS | **Not reportable** | *"Banner grabbing/Version disclosure"* (703); *"Verbose … without disclosing any sensitive information"* (681) |
| §6 `things.api` = API Gateway | **Not reportable** | Banner-level disclosure only; no PoC |
| §7 `link`/`em`/`go` email infra | **Not reportable** | *"Third party infrastructure"* (656) — out of scope |
| §8 `x-riv-env: prod_ue1` | **Not reportable** | *"Banner grabbing/Version disclosure"* (line 703) |
| §9 Datadog trace IDs | **Not reportable** | Not sensitive data; IDs are the caller's own |
| §10 `basecamp` wildcard CORS on static HTML | **Not reportable** | *"CORS misconfiguration on non-sensitive endpoints"* (line 683) |
| §11 `robots.txt` disclosures | **Not reportable** | Intentional; *"Verbose messages/files/directory listings without disclosing any sensitive information"* (line 681) |
| §12 Certificate SANs → `goriv.co` | **Not reportable** | Public data; *"Banner grabbing/Version disclosure"* |
| §13 `legacy.basecamp.rivian.com` remote | **Not reportable** | Component library only — no credentials, tokens or endpoints exposed |
| §14 `.goriv.co` session-cookie scoping | **Not reportable** (as found) | No browser-observable effect from this host (RFC 6265 domain-match) → no PoC; the exploitable direction needs the out-of-scope `goriv.co` estate |
| §15 second GraphQL entry + 4 backends | **Not reportable** | Architecture note; tells you where to aim post-auth, not a defect itself |
| §16 mutation-over-`GET` → `INTERNAL_SERVER_ERROR` on `gateway` only | **Not reportable** | No sensitive data, no proven impact → *"Verbose messages … without disclosing any sensitive information"* (681). Config-drift **lead** |
| §16 `GET` query execution on the Cosmo routers | **Not reportable** | Response unreadable (ACAO pinned to `https://rivian.com`); no side-effecting query identified → no PoC |
| §17 precise invalid-field oracle (`orders`, `business`) | **Not reportable** | A primitive, not a vulnerability — nothing to file unless used to reach sensitive schema. **Not used.** |
| §17 `serviceName: "scheduler"` subgraph leak | **Not reportable** | Minor internals disclosure; line 681 |
| §18 `/mobile/*` deep-link fallbacks | **Not reportable** | No web surface; app-only routing |
| §19 `/mobile/static/` anonymous asset pull | **Not reportable** | Public static assets by design; **listing denied**; nothing sensitive observed |
| §19 S3 `AccessDenied` XML on prefixes | **Not reportable** | *"Verbose messages … without disclosing any sensitive information"* (681) |
| §20 two Google API keys in the APK | **Not reportable** | *"Disclosed/misconfigured API keys (Maps, DD Monitoring, etc.)"* (711) + *"without proven business impact"* (675) + mobile (750). **Recommend rotate, do not file** |
| §20 "secrets" dump overall | **Clean negative** | No valid secret found; all other detectors were false positives |
| §21 pre-release R2 feature flags | **Not reportable** | Product-roadmap disclosure, not a security vulnerability |
| §21 internal Confluence URL in a shipped asset | **Not reportable** | Informational; host is third-party (Atlassian) → out of scope to test |
| §21 interior-camera / Gear Guard streaming | **Lead** | Not itself a finding — the testable question (viewing entitlement) is post-auth |
| §22 two new Cosmo gateways from the APK | **Not reportable** | Discovery, not a defect — but it expands the Tier-1 test surface |
| §22 `rivianservices.com` in the app | **Not reportable** | **Out of scope** — different registrable domain; recorded as do-not-touch |
| §23 `101` on the subscription WebSocket | **Not reportable as found** | `connection_init` refused `4400` ⇒ auth is enforced. The `101` alone is not missing auth |
| §24 new hosts (`login.`, `commauth.basecamp`) | **Not reportable** | Discovery, not a defect — but it *is* the RoE's declared basecamp scope |
| §25 `goriv.co` in the post-login redirect allowlist | **Hardening — best candidate** | Real misconfiguration, but the exploit needs a `*.goriv.co` host → **out of scope, untested**; the redirect is client-side so no `curl` PoC. Frame as hardening, not exploit |
| §25 `cookieDomain: basecamp.rivian.com` | **Not reportable** | Token scope spans `*.basecamp.rivian.com`; no sibling proven less trusted |
| §26 `resetmfaemail` account-existence oracle | **Not reportable** | *"Username enumeration"* (line 685) is excluded. Recorded as **hardening** — its sibling endpoint does it correctly |
| §26 unauthenticated MFA-reset initiation | **Unproven — do not file** | Would need a valid-token weakness to be a finding; testing that is brute force (banned) |
| §26 `resendrstpwdemail` unauthenticated mail primitive | **Not reportable** | *"Email bombing"* (line 699) excluded |
| §26 `resetmfaverify` rejects garbage tokens | **Clean negative** | No bypass found |
| §27 live Basecamp login attempt | **Clean negative** | No credential form exists — Cognito federates to Entra ID before any password is requested. **basecamp auth-bypass scope is closed** |
| §27 Fleet and Basecamp share one Entra tenant | **Not reportable** | Architecture, and arguably a *good* design (no password surface). Worth stating to the owner as blast-radius context |
| §28 Contentful `preview: true` | **Hardening — latent exposure** | Reachable unauthenticated; fails only because the preview token is invalid. Not a confirmed finding (no draft content returned), but a `preview` argument should not be exposed publicly at all. **Best framed as: latent draft-disclosure risk if the token is ever provisioned** |
| §28 `contactAttrCapture` accepts `subscribe_to_marketing` / `sms_notification` unauthenticated | **FINDING — see §29** | Tested with non-routable data. Anonymous write with `success: true`; impact caveat recorded |
| §29 `contactAttrCapture` anonymous CRM/identity write | **FINDING (candidate to file)** | Not cleanly excluded: not CSRF, not a mail flood. Risk a triager cites *"Email bombing"* (699) — frame as unauthenticated third-party consent enrolment, not spam. **Impact caveat must be stated up front** |
| §30 `sys { id }` harvest of published CMS structure | **Not reportable** | Published content only; a recon technique, not a defect |
| §31 `/gear-shop` → `gearshop.rivian.com` (carve-out) | **Not reportable** | A scope/process trap, not a Rivian defect — but it is the most likely way a tester wanders out of scope |
| §31 `/r3`, `/configurations/builder/r2` publicly live | **Not reportable** | Published marketing pages; unreleased-model material is intentional disclosure |
| §31 `/en-GB/gear-shop` → `/en-GB/en-GB` | **Not reportable** | Malformed locale redirect; no impact → would also fall under a "cosmetic" dismissal |
| §31 RSC flight payloads leak the route tree | **Not reportable** | Client-side route groups; no sensitive data. Useful as recon technique only |
| **§32 Fleet internal topology disclosure (`et-service-bastion`, `dt-gql-auth`, `dt-gql-account-manager`)** | **FINDING — best candidate to file** | Tier-1 host; unauthenticated internal service name + path + plain-HTTP internal URL + internal error taxonomy. Risk: triager cites *"Verbose messages … without disclosing any sensitive information"* (681). Frame as internal-topology information disclosure, **not** SSRF/RCE |
| §32 `ssoExchange` JWT validation (alg:none, wrong-key) | **Clean negative** | Both forged tokens → `Invalid credentials.` No signature bypass |
| §32 `AccountResetPassword` / `accountSetProvisionalUserPassword` | **Untested, deliberately** | Probing reset codes / input field names by trial is enumeration → RoE-banned |
| §33 consumer operations correctly gated | **Clean negative** | `UNAUTHENTICATED` on every Tier-1 attempt; validation-then-authz order is correct |
| §33 `vehicleOrders` (10 000-order page size) | **Clean negative** | `UNAUTHENTICATED` — no mass order disclosure |
| §33 `mediaUploadUrl` / `LogUploadURL($domain)` | **Clean negative** | `UNAUTHENTICATED` — no anonymous presigned upload, no caller-domain control |
| §33 `queryByRivianId` (home address + GPS) | **Clean negative** | `401 Not authenticated` on `/api/vs/gql-gateway`; tested with the operator's own `rivianId` |
| §21/§22 Play Integrity bundled, enforcement unproven | **Not reportable** | No evidence of a defect either way; would need a PoC |
| Rate limiting / no rate limit | **Explicitly not reportable** | *"Bypassing rate-limits or the non-existence of rate-limits"* (line 690) |
| Framework versions (Next.js/Vite/React/Cosmo/Apollo) | **Not reportable** | *"Banner grabbing/Version disclosure"*; also *"software is out of date … without a proof-of-concept"* |
| All *Tested and found clean* rows | Negative results — nothing to file | — |

**No submission was made. Nothing found meets the bar.**

---

## Artifacts

All under `recon/`. Every claim above is traceable to one of these files.

**Scope record**

| File | Content |
| --- | --- |
| `rivianbugbounty.RoE` | Rules of engagement — the scope record (never edited) |
| `roe-extract-scope.txt` | **Verbatim** RoE quotes: RoE panel (483-491), asset table (544-601), OOS prose (654-713) |
| `scope.json` | Machine-readable canonical scope: 9 in-scope assets, 9 carve-outs, 16 OOS rules |
| `probe-http.sh` | The RoE-compliant probe wrapper: required header, pinned UA, 1 req/s cap, GET/HEAD/OPTIONS |

**Phase 1 — listed assets**

| File | Content |
| --- | --- |
| `dns.txt` | A/AAAA/CNAME/MX/TXT/NS for the three listed hosts |
| `tls-certs.txt` | Certificate subject/issuer/SAN/validity per host |
| `http-fingerprint.txt` | Status line + full headers per in-scope URL |
| `http-bodies.txt` | Small `400`/`200` response bodies |
| `graphql-probe.txt` | Minimal `{__typename}` transcript with rationale |
| `graphql-introspection-{gateway,content,orders,business}.json` | The four introspection refusals (raw) |
| `graphql-sdl-{gateway,content,orders}.json` | `_service { sdl }` refusals — no SDL leak on any endpoint |
| `graphql-deep.txt` | First deep pass: `_service{sdl}`, APQ, invalid-field probes |
| `graphql-all4.txt` | **Full battery on all four endpoints** — the §16 matrix, raw |
| `graphql-get-csrf.txt` | GET-vs-CSRF differential (query, APQ, mutation over GET) |
| `apk-paths.txt` | **APK-derived path sweep** (19 paths, raw as supplied) |
| `apk-paths-enGB.txt` | Same paths followed into the `/en-GB/` locale prefix — the deep-link fallbacks |
| `mobile-static.txt` | `/mobile/static/` namespace: directory-marker object, `403` listing denial, mp4 |
| `apk-secrets-triage.txt` | **APK secrets triage — no valid secret; detector-by-detector, values deliberately not recorded** |
| `apk-new-endpoints.txt` | **APK DEX endpoint recovery** — the two new Cosmo gateways, the WS subscription URL, `rivianservices.com` (OOS), vendor endpoints |
| `gql-recovered-ops-unauth.txt` | **Real GraphQL operations replayed with no session** — `GetUserDetails`, `CreateCsrfToken`, chat query |
| `login-basecamp.txt` | `login.basecamp.rivian.com` + `returnUrl` handling (identical 200/518 B ⇒ client-side) |
| `login-basecamp-bundle.js` | Basecamp sign-in SPA (428,334 B) — **the auth config, allowlist and recovery routes live here** |
| `basecamp-authflow.txt` | OIDC discovery attempt on `commauth` (403 API Gateway) + authorize probe |
| `basecamp-authrestapi.txt` | The three recovery routes, exercised once each — **the enumeration inconsistency** |
| `basecamp-cognito-login.txt` | **One authorised login attempt** — Cognito `302`s to Entra ID; no credential form reached. No password/code/token stored |
| `creds/.auth-login-extract.json` | Credential *shape* extracted from the capture (gitignored, never committed) |
| `contactattrcapture-probe.txt` | **§29 — the anonymous CRM-write probe.** Non-routable payloads; includes the transient-error false lead and its correction |
| `newroutes.txt` | **§31 — new routes from the page payloads**, `/gear-shop` carve-out redirect, locale-router defect |
| `fleet-authops.txt` | **§32 — the Fleet auth operations and the internal-topology disclosure** (raw) |
| `consumer-ops-unauth.txt`, `consumer-ops-gateways.txt` | **§33 — 178 consumer operations and the gating matrix** across gateways |
| `consumer-highvalue.txt` | **§33 — the four highest-value ops tested and gated** (orders, upload URLs, invoice/PII query) |
| `contentful-idprobe.txt` | **§28/entryId — type-filter test.** Wrong-type IDs return `null`; `sys{id}` harvest works |
| `contentful-preview-probe.txt` | **SUPERSEDED — first attempt, guessed variables, invalid baseline.** Kept as a record of the error |
| `contentful-preview-retest.txt` | **The valid test** — exact app variables as positive control, then `preview` flipped (§28) |
| `nextjs-serveraction-origin.txt` | Server-Action Origin/token test — identical `403 Invalid csrf token`; interpretation corrected in-file (§28) |
| `graphql-matrix-final.txt` | The 5-vs-1 mutation-over-`GET` matrix (§16) |
| `authenticated-surface.txt` | Stale-session replay across four entry points — all correctly rejected |
| `ws-subscription-probe.txt` | Unauthenticated WebSocket probe: `101` then `4400` on `connection_init`; legacy subprotocol `426` |
| `creds/.gitignore` | Authenticated-testing session material is gitignored (precedent: `axelspringerse/creds/`) |
| `.gitignore` | Protects `android/` (529 MB + raw scanner dump), `creds/`, and stray key material from being committed |
| `cors-probe.txt` | Forged-origin matrix **+ positive control** |
| `wellknown-robots.txt` | `robots.txt`, `sitemap.xml`, `security.txt`, `manifest.json` sweep |
| `api-namespaces.txt` | Sweep of the robots-disclosed namespaces |
| `business-auth-and-routes.txt` | `business.rivian.com/auth/` + `rd=` behaviour, `/auth/api`, `/quad/api`, `/root/api` |
| `loose-ends.txt` | Catch-all vs real-route discrimination |
| `rivian-sitemap.xml`, `sitemap-path-summary.txt` | 1.12 MB sitemap + path-class inventory |
| `basecamp-main.js` | Basecamp SPA bundle (319,861 B) |
| `business-auth-bundle.js` | Business portal login bundle (1,205,795 B) — **MSAL/Entra ID, tenant id, `/token`, reCAPTCHA key** |
| `business-auth-endpoints.txt` | `/token`, `/logout`, `/graphql`, `/api/v2/`, `/auth` probe transcript — **the `.goriv.co` cookie evidence** |
| `legacy-remoteEntry.js` | `legacy.basecamp.rivian.com` module-federation remote (15,466 B) — exposed module list |
| `basecamp-asset-manifest.json` | Absent — returns the SPA catch-all (negative result) |

**Phase 2 — `*.rivian.com` wildcard**

| File | Content |
| --- | --- |
| `crt-rivian.json` | Raw `crt.sh` CT response (1,864 records, 630 KB) |
| `ct-subdomains.txt` | Extracted names: non-`rivian.com`, carve-outs, in-scope candidates |
| `ct-resolved.tsv` | DNS resolution of all 111 candidates (IPs + CNAME chains) |
| `ct-thirdparty-excluded.txt` | The 11 third-party SaaS hosts, with the CNAME that proves each |
| `ct-probe-targets.txt` | The 33 in-scope hostnames actually probed |
| `ct-http-fingerprint.tsv` | Per-host status / content-type / server / via / location |
| `ct-followups.txt` | Full headers + bodies for `gogoogle`, `googleguide`, `things.api`, `things.stage`, `offlease`, `api` |
| `ct-summary.txt` | Counts, boundary rules, internal-DNS-leak list |
| `dns-leads.txt` | DNS-only resolution of discovered leads (no traffic to them) |

### Reproduction highlights

```bash
cd bug-bounties/intigriti/rivianbugbounty

# --- RoE compliance is in the wrapper: header + 1 req/s cap -------------
P=./recon/probe-http.sh        # sends X-Intigriti-Username: eliam, sleeps 1s

# 1. the phantom IP-range gate: the RoE contains no IP range at all
grep -nEc '([0-9]{1,3}\.){3}[0-9]{1,3}|/[0-9]{1,2}[^0-9]|CIDR' rivianbugbounty.RoE   # -> 0
grep -ni 'ip range\|netblock\|ASN' rivianbugbounty.RoE                                 # -> none

# 2. the eight carve-outs, straight out of the asset table
sed -n '579,600p' rivianbugbounty.RoE     # every entry reads "Out of scope"

# 3. wildcard enumeration — ONE passive CT query, then filter, then probe
curl -sS 'https://crt.sh/?q=%25.rivian.com&output=json' -o recon/crt-rivian.json
jq -r '.[].name_value' recon/crt-rivian.json | tr ',' '\n' | sed 's/^[[:space:]]*//' \
  | tr 'A-Z' 'a-z' | grep -E '\.rivian\.com$' | sed '/^\*/d' | sort -u   # 120 names
#    -> drop the 9 carve-outs, the carve-out kin, and the CNAME-proven SaaS hosts

# 4. third-party SaaS is excluded on CNAME evidence, not by guess
dig +short gearshop.rivian.com CNAME      # shops.myshopify.com.
dig +short email.comms.rivian.com CNAME   # mailgun.org.
dig +short smetrics.rivian.com CNAME      # 0j3snbzwpr.data.adobedc.net.

# 5. fingerprint a Tier-1 URL
$P https://business.rivian.com/api -o /dev/null -D -     # 400 {"errors":[{"message":"empty request body"}]}

# 6. GraphQL is live but unauthenticated-only
$P https://rivian.com/api/gql/gateway/graphql -X POST \
   -H 'content-type: application/json' --data '{"query":"{__typename}"}'      # 200 {"data":{"__typename":"Query"}}

# 7. introspection is disabled on all four (one query each, no batching)
$P https://rivian.com/api/gql/orders/graphql -X POST \
   -H 'content-type: application/json' --data @/tmp/introspect.json   # INTROSPECTION_DISABLED

# 8. CORS: forged origins get nothing, the real origin gets ACAO + credentials
$P https://rivian.com/api/gql/gateway/graphql -X OPTIONS \
   -H 'Origin: https://evil.example' -H 'access-control-request-method: POST' -o /dev/null -D -  # no ACAO
$P https://rivian.com/api/gql/gateway/graphql -X OPTIONS \
   -H 'Origin: https://rivian.com'   -H 'access-control-request-method: POST' -o /dev/null -D -  # ACAO: https://rivian.com

# 9. the stub-host takeover check — target is Rivian-owned, so NO takeover
$P https://gogoogle.rivian.com/ | grep -o 'url=[^"]*'      # -> riviancurrent.com/page/3646
dig +short www.riviancurrent.com CNAME                     # rivianprod.service-now.com.
whois riviancurrent.com | grep -i registrar                # COM LAUDE (brand-protection registrar)

# 10. basecamp's SPA catch-all defeats status-code route discovery
$P https://basecamp.rivian.com/api/v2/health     -o /dev/null -w '%{http_code} %{size_download}\n'  # 200 1151
$P https://basecamp.rivian.com/zz-nonexistent    -o /dev/null -w '%{http_code} %{size_download}\n'  # 200 1151

# 11. §14 — the session cookie scoped to the OUT-OF-SCOPE sibling domain
$P https://business.rivian.com/token -o /dev/null -D - 2>/dev/null | grep -i 'set-cookie'
#   set-cookie: session=deleted; Max-Age=0; Domain=.goriv.co
#   set-cookie: session_prod=deleted; Max-Age=0; Domain=.goriv.co
#   (browser drops these - business.rivian.com does not domain-match .goriv.co)

# 12. §15 — the second, undisclosed GraphQL entry point on the same host
$P https://business.rivian.com/graphql      # 400 {"errors":[{"message":"empty request body"}]}
$P https://business.rivian.com/api/v2/      # 404 404 page not found   (Go, third backend)
$P https://business.rivian.com/auth -o /dev/null -D - | grep -i '^set-cookie'  # HAProxy route=

# 13. §13 — the component-library remote (in scope: matches *.rivian.com, not a carve-out)
$P https://legacy.basecamp.rivian.com/remoteEntry.js -o /dev/null -w '%{http_code} %{size_download}B\n'  # 200 15466B

# 14. §16 — mutation-over-GET: same product, two different behaviours
$P 'https://rivian.com/api/gql/gateway/graphql?query=mutation%7B__typename%7D'   # 405 INTERNAL_SERVER_ERROR
$P 'https://business.rivian.com/api?query=mutation%7B__typename%7D'             # 405 "Mutations can only be sent over HTTP POST"

# 15. §16 — GET executes queries on the Cosmo routers, blocked on the Apollo servers
$P 'https://rivian.com/api/gql/gateway/graphql?query=%7B__typename%7D'          # 200 {"data":{"__typename":"Query"}}
$P 'https://rivian.com/api/gql/orders/graphql?query=%7B__typename%7D'           # 400 CSRF block

# 16. §17 — the field-existence oracle, and the subgraph-name leak
$P https://rivian.com/api/gql/orders/graphql -X POST -H 'content-type: application/json' \
   --data '{"query":"{ me { id } }"}'    # Cannot query field "me" ... (precise oracle)
$P https://rivian.com/api/gql/content/graphql -X POST -H 'content-type: application/json' \
   --data '{"query":"{ me { id } }"}'    # 200 data.me=null + serviceName":"scheduler"

# 17. §16/§17 — no SDL leak anywhere (all four correctly refuse)
for u in gateway content orders; do $P "https://rivian.com/api/gql/$u/graphql" -X POST \
   -H 'content-type: application/json' --data '{"query":"{ _service { sdl } }"}'; echo; done
```

---

## Housekeeping

- 🚨 **Never commit `android/`.** It is **529 MB** of APK splits and it contains
  `rivian-secrets.txt`, a raw secrets-scanner dump. Neither was tracked when this
  engagement started — a plain `git add .` would have committed both, and a real
  credential in git history is permanent. A `.gitignore` was added (§Artifacts) which
  now excludes it; verified with `git check-ignore`. **The triage found no valid
  secret (§20), but that is not a reason to relax this.**
- **Never re-file the two Google API keys** without a demonstrated business impact —
  the RoE excludes disclosed API keys by name (§20). Rotate them.
- ⚠️ **`AGENTS.md` and the original `README.md` were wrong about scope.** Eight hosts
  they listed as in-scope (`assets`, `careers`, `demovehicles`, `feedback`,
  `internalshop`, `media`, `stories`, `view.e`) are marked **"Out of scope"** in the
  RoE asset table. This was corrected here. **Anyone resuming this engagement must
  treat those eight plus `cloud.e.rivian.com` as do-not-touch.**
- ⚠️ **`AGENTS.md`'s IP-range condition is unsatisfiable.** It asserts subdomain
  enumeration is in scope "within the stated IP range(s) only", but the RoE states no
  IP range. The engagement proceeded on the RoE (wildcard in scope, bounded by the
  five rules above); **`AGENTS.md` still needs fixing by its owner.**
- ⚠️ **`goriv.co` is a sibling estate, not scope.** It appears in the SAN list of an
  in-scope certificate. Do not follow it.
- ⚠️ **`rivianservices.com` is a second out-of-scope domain.** The Android app calls
  `api.rivianservices.com/tiling/*` for map tiles (§22). A different registrable domain
  is not `*.rivian.com`. Do not follow it either. **Both traps arrived via first-party
  artefacts** (a certificate, the app) — expect more.
- ⚠️ **11 third-party SaaS hosts were deliberately excluded.** Shopify, ExactTarget,
  Mailgun, Adobe, Google Sites, career.page, ldpgs, SparkPost. If a future pass
  touches any of them, it is out of scope. List: `recon/ct-thirdparty-excluded.txt`.
- ⚠️ **`legacy.basecamp.rivian.com` is referenced by in-scope JavaScript but is not in
  CT and not a listed asset.** Do not fetch without a decision.
- **Required header.** Every request must carry `X-Intigriti-Username`. The wrapper
  enforces this; do not bypass it with raw `curl`.
- **Rate limit.** The RoE publishes none. Keep the self-imposed **1 req/s** cap; the
  RoE bans brute force and treats missing rate limits as non-findings either way.

---

## Next

### Bottom line first

**No payable finding exists at this scope, and that is now measured rather than assumed.**
Every high-value surface has been tested and gates correctly: Fleet and Basecamp are
Entra-gated (§27); the consumer API's vehicle, key, PIN, payment, order, upload and
PII operations all return `UNAUTHENTICATED` (§33); the subscription socket refuses
`connection_init` (§23); and the RoE excludes — **by name** — enumeration, banner
disclosure, verbose errors, missing rate limits, API-key disclosure and subdomain
takeover, which is most of what the remaining surface yields.

The two candidates that do clear the bar, **§32** and **§29**, are **weak**, and the
honest forecast is that a triager **dismisses both**. Filing them anyway costs standing
with the program, which is worth more than a speculative $0–100.

### Do these two things first — they are free and they decide everything

1. **Ask the program owner for a vehicle-bound test account.** This is the single
   highest-value action available and it is not a technical one. A session bound to a
   *vehicle* reopens the entire §33 surface — 178 operations including remote commands,
   digital-key attestation, PIN management, live-camera tokens and payments — which is
   where this program's **$1,500–5,000** band actually lives. The RoE's own FAQ only
   offers owner-registration, which produces **no vehicle**, so nothing else reaches it.
   Ask plainly: *"can you provide a test account with a vehicle attached?"*
2. **Ask whether a partner-federated Entra identity is obtainable.** Fleet
   (`business.rivian.com`) and Basecamp share tenant `f798cb4f-…` (§27); without an
   identity in it, both are closed and their RoE-declared scope —
   *"authentication/authorization of the publicly available endpoints"* — is untestable.

### Ask-before-filing (the two candidates)

3. **§32** — put the question to the owner rather than filing blind: *is an internal
   service name, its path, and a plain-HTTP internal URL considered sensitive
   information, or is this covered by the verbose-messages exclusion?* If they say
   sensitive, file; if not, don't.
4. **§29** — ask whether `contactAttrCapture` **creates or updates** a contact and
   **enrols the address for marketing/SMS**. A yes completes the finding with no further
   writes into production. A no closes it. (Testing it yourself with a live inbox/phone
   you own is the alternative, and needs your consent, not my judgement.)

### If access arrives — the work, in order

5. **Streaming/camera entitlement (§21)** — Gear Guard live view and the interior camera
   (`pet_cam`/`INTERIOR_CAMERA`). The RoE's stated worst case is privacy invasion; this is
   the closest thing to it.
6. **Object-level authorization across the 178 consumer operations (§33)** — every one is
   gated pre-session, so the whole question is whether a *low-privilege* session reaches
   objects it does not own. `vehicleId`, `addressId`, `paymentMethodId` and `guestIdList`
   are the parameters to substitute.
7. **`preview: true` authenticated (§28)** — the draft-content path is reachable
   unauthenticated and fails only on a broken token; if the resolver picks the token from
   the caller's context, an authenticated session may read unpublished content.
8. **Introspection authenticated (§28)** — still genuinely unmeasured; the capture
   contains zero introspection attempts.
9. **Re-probe the subscription WebSocket with a token (§23)** — the entire subscription
   surface is untested.

### Cheap, still-open, pre-auth

10. **Classify every nav href as in-scope / carve-out / third-party before clicking
    anything again (`open-navtraps`).** `/gear-shop` → `gearshop.rivian.com` proves the
    navigation leads out of scope (§31).
11. **Exercise the newly found public routes (§31)** — `/configurations/builder/r2`,
    `/demo-drive/book`, `/trade-in/vehicle-info`, `/offers`, `/compare`.
12. **Work the seven gateways as a set (§22, §33)** — they have different schemas and
    different policies; an authz result on one proves nothing about another. Remember
    the routing trap: sending an operation to the wrong gateway yields *validation*
    errors, not authorization answers.

### Housekeeping

13. **Fix `AGENTS.md`** — remove the phantom IP-range condition and mark the eight
    carve-out hosts do-not-touch.
14. **Rotate the two Google API keys** found in the APK (§20) — RoE-excluded from bounty,
    but they are real keys in a shipped app.
15. **Treat the throwaway account password as burnt** (§28 operational note) — it appeared
    in this session's transcript.

---

## Change log

- **2026-09-26** — Scope reconciliation: read `rivianbugbounty.RoE` in full (911
  lines); extracted the asset table verbatim; **found that `README.md`/`AGENTS.md`
  listed eight RoE-"Out of scope" hosts as in-scope**, and that the `AGENTS.md`
  IP-range gate has no basis in the RoE (zero IP/CIDR tokens in the file). Canonical
  scope written to `recon/scope.json`.
- **2026-09-26** — Passive recon: DNS (3 listed hosts), TLS certificate SANs. TLS
  surfaced the out-of-scope `goriv.co` estate — recorded as do-not-touch.
- **2026-09-26** — HTTP fingerprinting of the four Tier-1 URLs, `rivian.com` and
  `basecamp.rivian.com`. Self-imposed 1 req/s, required header on every request.
- **2026-09-26** — Surface mapping: GraphQL (`{__typename}` ×1 each; introspection
  refused on all four), CORS with positive control, robots/sitemap/well-known, the
  robots-disclosed API namespaces, and the Basecamp SPA bundle. Distinguished real
  routes from catch-alls (`/root/api`, `basecamp /api/v2/*`).
- **2026-09-26** — **Wildcard phase.** Operator resolved the `AGENTS.md` IP-range
  discrepancy in favour of the RoE: `*.rivian.com` is in scope with no IP constraint.
  One passive `crt.sh` query (1,864 records) → 120 `rivian.com` names → 33 probed
  after removing 9 carve-outs, 1 carve-out kin and 11 CNAME-proven third-party SaaS
  hosts. 22 answered. Found the two S3 stub hosts and verified **no subdomain
  takeover**; catalogued 11 internal-only DNS records; identified API Gateway on
  `things.api`.
- **2026-09-26** — **Authenticated capture analysed.** Operator supplied a Burp session
  for the whole auth flow (throwaway account). Auth is **cookie-only** (`u-sess`), CSRF
  via a **`csrf-token` header** with a `_csrfSecret`/`_csrfToken` double-submit pair —
  no `Authorization` header anywhere. Recovered **real GraphQL operations** the schema
  refuses to give up: `query GetUserDetails { user { userId firstName lastName email } }`
  and `mutation CreateCsrfToken` on `orders`, plus a support-chat config query on
  `content`. Replayed **unauthenticated**: `CreateCsrfToken` works and mints a token
  (expected — needed pre-login), `GetUserDetails` is refused (`CSRF_TOKEN_EXPIRED`, no
  data), chat categories return public config. **No PII leak.**
- **2026-09-26** — **§33 extended: the four potential money-makers tested, all gated.**
  Went after the operations most likely to be payable: `vehicleOrders` (client-controlled
  `pageInfo size:10000`), `mediaUploadUrl` (presigned S3 upload), `LogUploadURL($domain)`
  (**caller-controlled domain** + returned signature `headers` — SSRF/credential-leak
  shape), and `getPastInvoices → queryByRivianId(id)` which returns
  `serviceAddress{address1 city state postalCode longitude latitude}` — **a customer's
  home address and GPS**. Every one returned `UNAUTHENTICATED` (the invoice query `401`
  on `/api/vs/gql-gateway`, where the field actually exists). Invoice tested with the
  **operator's own `rivianId`** only. **Conclusion: no anonymous PII, order or upload
  primitive exists in the consumer API.** Outcome statement corrected accordingly — this
  scope is unlikely to pay without owner-supplied vehicle/partner access.
- **2026-09-26** — **§32: new best-candidate finding — Tier-1 Fleet internal-topology
  disclosure.** Mined the Fleet login bundle for its real GraphQL operations and replayed
  them unauthenticated against `business.rivian.com/api`. The auth gates hold
  (`getUserRole`/`logout` → `401`; `businessLogin` → generic `Invalid credentials.`), and
  **JWT validation is sound** (`alg:none` and wrong-key JWTs → `Invalid credentials.`), but
  **`ssoExchange` proxies a caller-supplied token to an internal service and reflects its
  error**, leaking `http://et-service-bastion.et-service-bastion/v1/sessions` (internal
  host + path, plain HTTP), `dt-gql-auth`, `dt-gql-account-manager`,
  `BASTION_ERROR`/`REST_DATA_SOURCE_ERROR`. Filed honestly as **Low/Medium information
  disclosure**, not SSRF. Reset-code flows left **untested** (enumerating them is brute
  force).
- **2026-09-26** — **§33: the consumer app's 178-operation surface, and the gating that
  closes it.** Extracted the full client operation inventory from the APK — remote command
  (`SendRemoteCommand`, `SendVehicleOperation`), digital-key crypto
  (`CreateSigningChallenge`), PIN, payments, live-camera tokens, addresses. Most take
  explicit `vehicleId`/`addressId`/`paymentMethodId` → textbook BOLA. **Tested
  unauthenticated on the correct Tier-1 gateway and every one returned
  `UNAUTHENTICATED`** — fields pass validation, authz then refuses, which is correct. Also
  mapped schema routing: these ops live on `rivian.com/api/gql/gateway/graphql`, *not*
  `api.rivian.com/graphql` or `/api/vs/gql-gateway`.
- **2026-09-26** — **§31: full response-body review of the capture.** Reviewed all 50
  distinct request/response pairs. Found: **a scope trap in Rivian's own navigation** —
  `/gear-shop` **`301`s to `gearshop.rivian.com`, an explicit RoE carve-out**, so
  following the menu walks a tester out of scope; **new public routes** recovered from
  the Next.js page props, including **`/r3` (live: "Rivian R3: Electric Crossover")** and
  a **live `/configurations/builder/r2`**; a **locale-router defect**
  (`/en-GB/gear-shop` → `/en-GB/en-GB`); and that the 43 KB "JSON" bodies are **RSC flight
  streams that leak the internal route tree** — including route groups `(authed)`/`(nav)`
  invisible in any URL — giving a client-derived route-enumeration technique that beats a
  wordlist. Negatives from the same pass: **no Contentful delivery/preview token** anywhere,
  no new subdomains, no `goriv.co`/`rivianservices.com` in any HTTP body, no AWS keys/ARNs,
  no internal endpoints.
- **2026-09-26** — **§29: first *finding*-tier item — `contactAttrCapture`.** Operator
  asked for it to be tested since it is exposed. Confirmed an **anonymous** `POST`
  (no session, no `Csrf-Token` header) executes `mutation contactAttrCapture` and
  returns **`success: true`**, accepting `subscribe_to_marketing: true` +
  `sms_notification: true` with arbitrary, unverified email/phone/name/postal-code.
  Apollo's CSRF prevention does not apply because a JSON POST is non-simple — which is
  correct behaviour, not a bypass; the defect is that **nothing else gates the write**.
  Tested with **non-routable data** only (`example.com`, fictional `555-0100`).
  **Impact caveat stated up front:** `isNewContact` never returned `true` and the
  downstream errored intermittently, so creation is unproven. **Self-corrected a
  mid-probe error:** an intermediate run concluded the CSRF token was the gate, but the
  no-token call succeeded on repeat — that had been a transient failure.
- **2026-09-26** — **§30: the Contentful `entryId` question answered.** Operator asked
  whether the ID is a hash/base64, whether it relates to the category, and whether new
  ones could be found on the assumption that the ID is treated as a control. Findings:
  it is a **random 22-char Contentful ID**, not a digest and not reversible; the link to
  the slug is a **parent reference** (`formSectionsCollection` → `sys.id`); and the
  "assume it's a control" hypothesis is **refuted** — four valid IDs of the wrong type
  all returned `null`, so the resolver **enforces a type filter**. `sys { id }` *is*
  harvestable on public queries, which walks the published CMS graph, but it cannot
  reach unpublished content. ID guessing cannot work; recorded so nobody tries.
- **2026-09-26** — **CORRECTION: the Contentful `preview` conclusion was re-derived.**
  Operator challenged the claim that `preview: true` was "correctly locked". They were
  right that my **baseline was broken**: I had used guessed variables
  (`categorySlug:"vehicle-registration"`, `entryId:"<slug>"`), and the capture shows the
  app uses `categorySlug:"registration-and-fees"` and a real
  **Contentful entry ID** `1WFBjmjn2IHLT07sXQ9USO` — and **never sends `preview` at
  all**. Re-ran with those exact values as a **positive control**: both queries return
  real data, `preview: false` is byte-identical, and `preview: true` fails with Contentful
  `ACCESS_TOKEN_INVALID`. The **outcome** (no draft disclosure today) stands, but the
  **interpretation was wrong**: this is a **latent exposure**, not a hardened control —
  the draft path is reachable unauthenticated and fails only on a broken token. Revised
  §28 accordingly, kept the failed attempt as evidence, and added a hypothesis that
  `preview: true` may succeed **when authenticated**. Methodology note: a broken
  baseline is not a control.
- **2026-09-26** — **Authenticated operation set mined from the capture (§28).** Extracted
  **7 distinct operations** from 32 authenticated requests — four previously unknown.
  Notably a **richer `getUserDetails` carrying `phone` + `address`** (refused
  unauthenticated, no leak) and two **Contentful** queries taking a **`$preview`
  parameter**. Tested the preview flag: **`preview:true` fails closed with Contentful
  `ACCESS_TOKEN_INVALID`** — the preview token is not provisioned publicly, so **no
  draft disclosure**, and the backend is confirmed Contentful. Also found the capture
  contains **zero introspection attempts**, so *"introspection when authenticated"*
  remains an **unanswered** question needing a fresh session. And discovered the
  `/auth` app is **Next.js Server Actions** (`Next-Action` hash + `text/plain` body):
  a forged-`Origin` test returns an identical **`403 Invalid csrf token`** for every
  Origin, showing an **application-level CSRF token dominates** — no login-CSRF.
- **2026-09-26** — **Matrix completed (5-vs-1) + stale-session negative.** Ran the
  battery on the last un-tested endpoint (`business.rivian.com/graphql`) and filled the
  gaps on the two APK gateways. **Five Cosmo routers return the correct `405` on
  mutation-over-`GET`; `rivian.com/api/gql/gateway/graphql` alone returns a 500-class
  `INTERNAL_SERVER_ERROR`** (§16) — the drift finding is now 5-vs-1 and hard to read as
  noise. All Cosmo routers disable introspection and enable APQ identically. Also
  replayed the captured session: **it had expired**, and every entry point rejected it
  correctly (`consumer-ui` → `null`, `me` → `UNAUTHENTICATED` ×2, `GetUserDetails` →
  `CSRF_TOKEN_EXPIRED`). A clean negative for the auth controls, and the reason
  authenticated testing is blocked pending a **fresh** session.
- **2026-09-26** — **Basecamp login attempted (§27) — and the auth-bypass scope closed.**
  Operator authorised one live attempt. Cognito `/oauth2/authorize` returned **`302`
  straight to Entra ID** — **no credential form exists**, so **no credential was ever
  transmitted** and the redirect was not followed into Microsoft. The federated tenant
  is **`f798cb4f-…`, the same one the Fleet portal uses**, so **Fleet and the partner
  portal are one identity plane** — which reframes §25's `goriv.co` trust as a single
  plane trusting the sibling domain twice, not two coincidences. Net: the RoE's
  *"scope of testing for this domain is authentication bypass"* has **no pre-auth
  password surface to attack** — a correct design, and an honest dead end without a
  partner-federated Entra identity.
- **2026-09-26** — **Basecamp auth findings (§24-§26).** Recovered two new in-scope hosts
  (`login.basecamp.rivian.com`, `commauth.basecamp.rivian.com`) and the full auth
  design: **Cognito, OAuth2 authorization_code + PKCE, state validated** — built
  correctly. Two issues: **(§25) the post-login redirect allowlist is a *suffix* list
  containing `goriv.co` and `scm.goriv.co`** — making `goriv.co` the **second**
  independent auth mechanism to trust that out-of-scope sibling domain (§14 was the
  first) — the strongest finding candidate, though the exploit precondition
  (`*.goriv.co` control) is out of scope and the redirect is client-side. **(§26)** the
  auth REST API's `resetmfaemail` returns `404 "User not found"` while its sibling
  `resendrstpwdemail` is enumeration-resistant (`200` always) — an inconsistency worth
  fixing, though enumeration is RoE-excluded. `resetmfaverify` rejects garbage tokens.
  All recovery probes used **only the operator's own address**.
- **2026-09-26** — **APK DEX endpoint recovery + WebSocket probe.** Extracted strings
  from `classes*.dex` (145 URLs) and **found three in-scope endpoints that no sweep had
  reached**: **`api.rivian.com/graphql`** and **`rivian.com/api/vs/gql-gateway`** (two
  more Cosmo routers) and **`wss://api.rivian.com/gql-consumer-subscriptions/graphql`**
  (§22). That takes the known GraphQL surface to **six HTTP endpoints + one WebSocket**
  and **corrects** the earlier claim that `api.rivian.com` was unmappable. Also
  recovered `rivian.com/account/handoff` → `/en-GB/auth/handoff` (CSRF tokens +
  LaunchDarkly-style flag-context cookie), and a **new out-of-scope domain**,
  **`api.rivianservices.com`** (map tiles) — recorded as do-not-touch alongside
  `goriv.co`. Probed the subscription socket: `101` upgrade succeeds, but
  **`connection_init` with no token is refused `4400`** and the legacy subprotocol
  gets `426` — **auth is correctly enforced** (§23). The two new gateways also made
  the §16 drift finding much stronger: **3 of 4 Cosmo routers handle mutation-over-`GET`
  cleanly; `gateway` alone 500s.** Added `creds/` (gitignored).
- **2026-09-26** — **APK source and secrets review** (operator invitation).
  Triaged `rivian-secrets.txt` → **no valid secret**; ~100% scanner false positives
  (ASN.1 OIDs as "IPs", English prose as "Basic auth", a Stripe SDK signature as a
  "Generic Secret", zero JWT-shaped strings). Only real-shaped items are **two Google
  API keys**, RoE-excluded by name → recommend rotate, not file (§20). Read
  `assets/whatsnew.json` → **three unreleased R2 features gated on client-side flags**,
  including **`pet_cam` / `INTERIOR_CAMERA` (in-cabin camera)**, which pairs with the
  **AWS Kinesis Video Streams + WebRTC + WebSocket signalling** Gear Guard live-view
  stack in `android/cloud/webrtc/` — flagged as the **highest-value post-auth lead**
  given the RoE's *"Privacy invasion"* priority (§21). Also found an internal
  Confluence URL shipped in `whatsnewMock.json` (informational; third-party host).
  Added `.gitignore` — **`android/` was 529 MB untracked and unprotected**.
- **2026-09-26** — **APK-derived path sweep** (operator supplied 19 paths from
  `com.rivian.android.consumer`). All `/mobile/*` routes are **app-only deep links**:
  on the web they `307` to `/en-GB/download` (or, for one, to a real support article),
  so there is no web-reachable surface behind them (§18). Found that
  **`/mobile/static/` is a public S3-backed asset namespace** serving app content
  anonymously (a 7.2 MB release-notes video for app v2.5.0), with **`ListBucket`
  correctly denied** (`403 AccessDenied`) and `/mobile/static/` itself being a 2021
  zero-byte directory-marker object, not a live listing (§19). Also confirmed the
  APK's trailing-slash GraphQL URL `/api/gql/content/graphql/` behaves **identically**
  to the unslashed form — no normalization differential. Still nothing submittable.
- **2026-09-26** — **Full GraphQL battery on all four endpoints** (operator request).
  Ran shape / SDL / APQ / field-oracle / GET-CSRF / mutation-over-GET probes against
  `gateway`, `content`, `orders` and `business/api`. Results: mutations refused over
  `GET` on all four (good); **both Cosmo routers execute `GET` queries while both
  Apollo servers block them**; and the two Cosmo routers **disagree** on
  mutation-over-`GET` — `business` returns a correct `405`, `gateway` returns a
  500-class `INTERNAL_SERVER_ERROR`, i.e. **config/version drift** (§16). Also
  confirmed `me` on three of four, and found `content` leaking the subgraph name
  `serviceName: "scheduler"` (§17). No `_service { sdl }` leak anywhere. No
  submittable finding — recorded as hardening + two leads.
- **2026-09-26** — **No submission made.** No finding survived the RoE filter;
  everything is hardening or informational. Blocked on credentials for the areas the
  RoE cares about most (Basecamp auth bypass, Fleet authn/authz).
- **2026-09-26** — **Pre-auth bundle deep-dive** (second pass, after a challenge that
  nothing looked actionable). Fetched the Business portal login bundle (1.2 MB) and
  `legacy.basecamp.rivian.com/remoteEntry.js`. Found: the Fleet portal authenticates
  via **MSAL → Entra ID** (tenant `f798cb4f-…`); a **second, undisclosed GraphQL entry
  point** at `business.rivian.com/graphql`; a fourth backend (`/api/v2/*`, Go); a
  session cookie scoped to the **out-of-scope `Domain=.goriv.co`** (§14 — no
  browser-observable effect, RFC 6265); and that `legacy` is a **component-library**
  remote, not an API. **Corrected the earlier `/api/v2/` misreading — it is the
  Datadog RUM proxy, not a Basecamp business API.** Result unchanged: no submittable
  finding; the actionable work is all credential-gated.

```
(\_/)
(o.o)
(> <) rabbit-hole-research
```
