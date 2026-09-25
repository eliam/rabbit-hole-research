# UZ Leuven — Intigriti engagement notes

Running notes for the **UZ Leuven** program on Intigriti (Public / Open, Hospitals & Healthcare).
Reference: `uzleuven.RoE`. All testing is within the published RoE.

## Rules of engagement (observed)

- **Max 5 requests / second** — never exceeded.
- **No automatic scanners** — manual, targeted requests only.
- **Required request header**: `X-Intigriti-Username: eliam` on every request.
- No tooling against contact forms. No DoS/brute force.
- Zero-days: reportable, but usually no bounty within 14 days of a patch.
- Safe harbour applies.
- Program is explicitly interested in **leaking of personal/medical data** and **administrative access**.

## Scope (from `uzleuven.RoE`)

| Tier | Assets |
| --- | --- |
| Tier 1 | `autodiscover`, `ecrf`, `extranet-asa`, `extranet`, `liquidfiles`, `mx1`, `mx2`, `pcrstudioruzb`, `prddsplunkhf`, `sts`, `www` `.uzleuven.be` |
| Tier 2 | `193.58.149.121,98,82,101,107,108,111`; `wp5-truststroke`, `cardsonline.azdiest.be`, `liquidfilestest`, `random.uzleuven.be/random/`, `teststs`, `w1`, `cardsonlinetst.azdiest.be` |
| Tier 3 | `*.kwsdose.be`, `*.playuzleuven.be`, `*.uzleuven.*` |
| No bounty | `*.contactallerg(y\|ie)`, `*.mir`, `*dev`, `*idp*`, `*stag*`, `files`, `kumulus`, `mijnacc`, `mirc`, `prddnighting01`, `w1/random`, `ziekenhuisschool.be` |
| Out of scope | `jobs`, `vacatures`, `uzleuven.atlassian.net`, `boekentoy.*`, `uz-laboboeken.firebase*`, `laboboeken.uzleuven.be` |

## Environment

| Target | Role | Notes |
| --- | --- | --- |
| `extranet.uzleuven.be` | Ivanti Connect Secure **VPN gateway** | `193.58.149.120` |
| `sts.uzleuven.be` | **ADFS** IdP (SAML/OIDC) | `193.58.149.108` |
| `idp.iamfas.belgium.be` | Belgian FAS / itsme IdP | third party — not in scope |

---

## Findings

### 1. `extranet.uzleuven.be` — Ivanti Connect Secure (Tier 1)

Product fingerprinted from `/dana-na/auth/...` responses: `Copyright (c) 2023 by Ivanti Inc.`,
EUP sign-in UI (`/dana-na/css/eup_signin.css`), `bootstrap-3.4.1`. Build date
`Last-Modified: Wed, 07 Jan 2026 18:38:58 GMT` on `/dana-na/css/signin.css` → **recently patched**
(2023/2024/2025 pre-auth CVEs ruled out by patch level).

**Sign-in URLs (stable, not per-request):**

| Entry | Sign-in URL | Purpose |
| --- | --- | --- |
| `/` | `url_pILuuvz3DlTY4iVo` | custom branded landing page |
| `/adfs` | `url_4oTd2p4a0itcgdvM` | realm `Soft Token (adfs)` → ADFS |
| `/fas` | `url_ZngUmyh877yGwQwK` | realm `Eid - ItsMe` → Belgian FAS/itsme |
| `/old` | `url_default` | legacy username/password sign-in page |

The landing page keeps the `/old` link **commented out**, but the legacy `url_default` page remains
reachable. It renders a username/password form with a `realm` dropdown listing only
`Soft Token (adfs)` and `Eid - ItsMe`.

**Tested and negative:**

| Probe | Result |
| --- | --- |
| `login.cgi?realm=<any>` | realm-validity oracle only; valid → IdP redirect, invalid → `?p=failed`. No unauthenticated/local realm. |
| Legacy password form | inert — both realms are federated, submitted creds are ignored |
| SAML forgery — unsigned `SAMLResponse` POSTed to `saml-consumer.cgi` | rejected: `FAILURE: No valid assertion found in SAML response` → **signature validation enforced** |
| `SAMLart` artifact handling | SP is POST-binding (`FAILURE: SP is configured for post binding`) |
| `?p=` / `signinId` traversal (`../../../../etc/passwd`) | no traversal; `/dana-na/` → `400 Invalid Path` |
| `url_admin/welcome.cgi` | `You do not have permission to login` |
| `/dana-ws/<url>` `DSLaunchURL` cookie | AES-CBC token (16-byte IV + ciphertext) — not forgeable |
| `/dana-na/user/getUserSession`, `/dana-na/help/`, `/dana-cached/` | 404 / 400 / redirect to auth |

`SAMLart` error messages leak the SP's binding configuration (`Detail: ...`), information-only.
**No exploitable defect identified on the gateway.**

### 2. `sts.uzleuven.be` — ADFS IdP (Tier 1)

| Check | Result |
| --- | --- |
| `/adfs/ls/idpinitiatedsignon.aspx` | **200 — publicly enabled** |
| Relying-party inventory | **55 RPs disclosed** by name in the sign-on page |
| IdP-initiated SSO | functional — `?loginToRp=<GUID>` renders an RP-bound sign-in page |
| `/adfs/.well-known/openid-configuration` | 200 — OIDC enabled (`issuer https://sts.uzleuven.be/adfs`) |
| Scopes advertised | `openid profile email allatclaims user_impersonation vpn_cert logon_cert winhello_cert aza ugs` |
| Grants advertised | `authorization_code refresh_token client_credentials jwt-bearer implicit password device_code` |
| `/FederationMetadata/2007-06/FederationMetadata.xml`, `/adfs/services/trust/mex` | 200 (public by design) |
| `/adfs/portal/` | 404 |

`sts.uzleuven.be` does **not** match the No-bounty `*idp*.uzleuven.be` pattern and is listed Tier 1.

**Candidate finding (Low / informational):** IdP-initiated sign-on page left publicly enabled →
unauthenticated relying-party enumeration (55 apps, incl. internal tooling) and an
IdP-initiated SSO entry point (`loginToRp`). Impact requires an RP that accepts unsolicited assertions.

**Relying parties disclosed** (id → name) are captured in `recon/05_idpinitiatedsignon.html`,
including `extranet.uzleuven.be`, `liquidfiles.uzleuven.be`, `gitlab-UZL`,
`jenkins.gcp.uzleuven.be`, `keycloak.mir.uzleuven.be`, `patientsafety`, `SentinelOne`,
`Patch Manager Plus PROD`, Taleo, AWS.

---

### 3. `ecrf.uzleuven.be` — clinical eCRF (Tier 1) — **not testable**

Resolves to **Cloudflare** (`104.18.4.60`, `104.18.5.60`), not to UZ Leuven infrastructure.
Every request (browser-like headers, RoE header present, ≤5 req/s) returns:

```
HTTP/2 403
server: cloudflare
cf-ray: a40d6ad20b54ef0b-LHR
<body> "Sorry, you have been blocked" ... Ray ID
```

This is a Cloudflare WAF **block rule** (not a JS/managed challenge) applied to our source IP.
The origin is not reachable from this host, so `ecrf` cannot be assessed. Likely needs an IP
allow-list from the program. **Open question: request source-IP allow-listing, or test from a
permitted network.**

### 4. `liquidfiles.uzleuven.be` / `liquidfilestest.uzleuven.be` — LiquidFiles (Tier 1 / Tier 2)

LiquidFiles file-transfer appliance (Ruby on Rails + nginx), `193.58.149.82`, branding
"UZLeuven Liquidfiles" / "LiquidfilesTest". Customised banner, support mailto, no version footer.

**Authentication surface:**

| Endpoint | Behaviour |
| --- | --- |
| `/login` | local email/password login (enabled **alongside** SSO) |
| `/saml` | 302 → `https://sts.uzleuven.be/adfs/ls/?SAMLRequest=…` (ADFS SSO) |
| `/saml/metadata` | 200 — SP metadata (public) |
| `/saml/consume` | SAML ACS (POST binding) |
| `/password_reset/new` | 200 — self-service reset |
| `/messages`, `/admin` | 302 → `/` (auth required) |

**SP metadata** (`/saml/metadata`, both instances):

```xml
<md:EntityDescriptor entityID="https://liquidfiles.uzleuven.be/">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="false" ...>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="...HTTP-POST"
        Location="https://liquidfiles.uzleuven.be/saml/consume" index="0" isDefault="true"/>
```

**SAML validation test — negative (secure):** POSTing an unsigned, self-crafted `SAMLResponse`
(NameID `eliam@intigriti.me`, correct audience/ACS/Destination) to `/saml/consume` is rejected:

```
Invalid SSO Response: Found an unexpected number of Signature Element. SAML Response rejected
```

That string is emitted by the **`ruby-saml`** gem's `validate_one_signature` — i.e. the SP
requires exactly one `ds:Signature` and does verify it. No unsigned/self-signed bypass.
`WantAssertionsSigned="false"` only reflects that ADFS signs the *Response*, not the *Assertion*.

**Not exploitable without credentials.** The residual risk is a `ruby-saml` version check
(CVE-2024-45409 signature wrapping; CVE-2025-25291/25292 parser differential), but every published
PoC needs a **validly signed** SAML response as a base, which requires an account the program does
not provide. Worth noting only if a signing oracle can be obtained.

**Other checks — negative:** `/api/v1/*` 404, `/filedrop` 404, `/upload` 404, `/sidekiq` 404,
`/rails/info/routes` 404 — no debug/admin exposure; self-registration and anonymous upload appear
disabled; 404/error pages are branded with no framework detail.

### 5. `teststs.uzleuven.be` — ADFS **test** (Tier 2)

Same exposure as prod, reachable (unlike the Cloudflare-blocked hosts):

| Endpoint | Result |
| --- | --- |
| `/adfs/ls/idpinitiatedsignon.aspx` | 200 — IdP-initiated sign-on **enabled** |
| RPs disclosed | 5 — `extranet-test.uzleuven.be`, `leerplatform.azdiest.be TEST`, `patientsafety TEST`, `upckuleuven-test.ultimo.net`, `Xibo TEST` |
| `/FederationMetadata/2007-06/FederationMetadata.xml` | 200 |
| `/adfs/.well-known/openid-configuration` | 200 |
| `/adfs/services/trust/mex` | 200 |

### 6. Host reachability sweep (Tier 1 / Tier 2)

| Host | Result |
| --- | --- |
| `extranet.uzleuven.be` | Ivanti ICS — assessed, §1 |
| `sts.uzleuven.be` | ADFS — assessed, §2 |
| `teststs.uzleuven.be` | ADFS test — reachable, §5 |
| `liquidfiles.uzleuven.be` | LiquidFiles, `193.58.149.82` — assessed, §4 |
| `liquidfilestest.uzleuven.be` | LiquidFiles test — assessed, §4 |
| `pcrstudioruzb.uzleuven.be` | **OpenSAML/Shibboleth SP** — 302 → `extranet.uzleuven.be/dana-na/auth/saml-sso.cgi?...&SigAlg=…rsa-sha256` (SP-initiated SSO through the ICS gateway). Reachable. |
| `autodiscover.uzleuven.be` | Exchange Autodiscover — `Microsoft-HTTPAPI/2.0`, 302 |
| `www.uzleuven.be` | Public web site — `CloudFront`, 301 |
| `prddsplunkhf.uzleuven.be` | **HTTP 522 from Cloudflare** (origin unreachable to CF) |
| `ecrf.uzleuven.be` | **Cloudflare block (403)** for our IP — see §3 |
| `wp5-truststroke.uzleuven.be` | Cloudflare 403 (blocked) |
| `random.uzleuven.be` | Cloudflare 403 (blocked) |
| `w1.uzleuven.be` | Cloudflare 403 (blocked) |
| `extranet-asa.uzleuven.be` | connection **timeout** (filtered) |
| `mx1.uzleuven.be`, `mx2.uzleuven.be` | connection **timeout** (filtered; no HTTPS) |

**Net effect:** roughly half the in-scope estate is either WAF-blocked for our source IP or
firewalled. Any assessment of `ecrf`, `wp5-truststroke`, `random`, `w1`, `prddsplunkhf`,
`extranet-asa`, `mx1`, `mx2` requires **source-IP allow-listing** or a permitted network.

### 7. Scanner run — IP inventory (`runs/2026-09-25_22-27-18`, box *sirius*)

`masscan` then `nmap -sT -Pn -p 80,443 -sV --version-light` across the RoE Tier-2 IP range
(`193.58.149.82/98/101/107/108/111/121`).

| IP | PTR | Open | Notes |
| --- | --- | --- | --- |
| `193.58.149.82` | **`lbuzldmz01.uzleuven.be`** | 80, 443 nginx | shared **load balancer**; TLS `CN=*.uzleuven.be` |
| `193.58.149.98` | `mail.playuzleuven.be` | 80 nginx | 301 → https, but **443 not listening** (dead redirect) |
| `193.58.149.101` | `mail.uzleuven.be` | 80, 443 nginx | **Exchange 2019** (`15.2.2562`) |
| `193.58.149.107` | `teststs.uzleuven.be` | 443 | ADFS test (§5) |
| `193.58.149.108` | `sts.uzleuven.be` | 443 | ADFS prod (§2) |
| `193.58.149.111` | — | none | filtered / timeout |
| `193.58.149.121` | — | none | filtered / timeout |

**`.82` is a shared LB** — Host-header probing shows it serves **only** `liquidfiles.uzleuven.be`,
`liquidfilestest.uzleuven.be` and `pcrstudioruzb.uzleuven.be`; every other `*.uzleuven.be` Host gets
the nginx default-deny `403`. So the Cloudflare-blocked origins are **not** reachable through it.

**`.101` is a multi-tenant Exchange.** Its certificate (`CN=mail.uzleuven.be`) carries 35 SANs:
mail/autodiscover for UZ Leuven **plus ~15 partner organisations** (`vkvlaamsbrabant.be`, `viapluz.be`,
`pvtandreas.be`, `mscenter.be`, `hospex.be`, `limmerik.be`, `reakiro.be`, `vcns.be`, `vznkul.be`,
`debakermat.be`, `dehulster.be`, `zorgkuleuven.be`, `cgg-vbo.be`, `upckuleuven.be`, `azdiest.be`,
`migrmail.uzleuven.be`).

> ⚠️ **Scope discipline:** only the `uzleuven.be` names are in scope (`*.uzleuven.*` Tier 3;
> `autodiscover.uzleuven.be` Tier 1). The partner-org domains are **not** in the RoE and were **not**
> tested. `mail.azdiest.be` / `autodiscover.azdiest.be` specifically are out of scope (only
> `cardsonline[ tst].azdiest.be` is listed).

**Exchange surface (in-scope names only):**

| Endpoint | Result |
| --- | --- |
| `/owa/` | 302 → `sts.uzleuven.be/adfs/ls/?wa=wsignin1.0&wtrealm=…/owa/` (ADFS WS-Fed) |
| `/owa/auth/logon.aspx` | 200 but **form-less** — JS `location.href='../'`; no form/Basic fallback |
| `/EWS/Exchange.asmx` | 401 (Basic/NTLM) |
| `/ecp/`, `/rpc/`, `/PowerShell/` | 502 (backend not exposed) |
| `/mapi/` | 404 |
| `POST /autodiscover/autodiscover.xml` (`EMailAddress=test@example.com`) | **401** — no cross-domain redirect for unauthenticated callers |

OWA logon HTML references an internal host `http://exweb/14/Specs/E14` (internal naming; informational
only, and "banner grabbing/version disclosure" is out-of-scope per the RoE).

**Passive PTR sweep of `193.58.149.0/24`** (DNS only — no traffic sent to any unlisted IP):

| IP | PTR | Role |
| --- | --- | --- |
| `.62` | `fortinet-v353.uzleuven.be` | FortiGate firewall |
| `.72` | `prdpumbrella1.uzleuven.be` | Cisco Umbrella node |
| `.73` | `prdaumbrella1.uzleuven.be` | Cisco Umbrella node |
| `.82` | `lbuzldmz01` | LB *(in RoE IP list)* |
| `.83` | `prddadfsprox01` | **ADFS proxy / WAP** |
| `.84` | `prddadfsprox02` | ADFS proxy / WAP |
| `.85` | `tstdadfsprox01` | ADFS proxy (test) |
| `.86` | `tstdadfsprox02` | ADFS proxy (test) |
| `.87` | `plydadfsprox02` | ADFS proxy (play) |
| `.98` | `mail.playuzleuven.be` | *in RoE IP list* |
| `.101` | `mail.uzleuven.be` | Exchange — §7 *in RoE IP list* |
| `.107` | `teststs.uzleuven.be` | ADFS test *(in RoE IP list)* |
| `.108` | `sts.uzleuven.be` | ADFS prod *(in RoE IP list)* |
| `.110` | `prdlbuzldmz02` | LB |
| `.111` | `sftp.uzleuven.be` | SFTP *(in RoE IP list)* |
| `.112` | `prdaisa6001-ext` | perimeter |
| `.113` | `prdpisa6001-ext` | perimeter |
| `.114` | **`extranet-2.uzleuven.be`** | **second Ivanti ICS** |
| `.118` | `prdaisa6000-ext` | perimeter |
| `.119` | `prdpisa6000-ext` | perimeter |
| `.120` | `extranet.uzleuven.be` | ICS (Tier 1) |
| `.121` | `prdalbuzldmz01` | LB *(in RoE IP list)* |
| `.122` | `prdplbuzldmz01` | LB |
| `.124` | `prdplbuzldmz02` | LB |
| `.125` | `prdalbuzldmz02` | LB |
| `.126` | `fortinet-v253` | FortiGate firewall |

The guess of a `…02` was correct — the LB family is
`lbuzldmz01` / `prdlbuzldmz02` / `prdplbuzldmz01-02` / `prdalbuzldmz01-02` (four more found purely by PTR).

**New resolvable in-scope hostnames** (they match `*.uzleuven.*`, Tier 3):

| Name | IP | Note |
| --- | --- | --- |
| `extranet-2.uzleuven.be` | `.114` | **identical ICS configuration** to the Tier-1 `extranet` — same sign-in URLs (`url_pILuuvz3DlTY4iVo`, `url_4oTd2p4a0itcgdvM`, `url_default`); `/old` present too |
| `sftp.uzleuven.be` | `.111` | no HTTP(S) response; `22/tcp` filtered from our network |
| `prdlbuzldmz02.uzleuven.be` | `.110` | LB |

`lbuzldmz01/02` and `prdalbuzldmz01/02` have **no forward DNS** — PTR-only names, reachable only as
IP + `Host:` header.

> ⚠️ **Scope caution:** the RoE enumerates **7 IPs** (`.82 .98 .101 .107 .108 .111 .121`). The other
> addresses above were only *resolved* (PTR), never contacted. The matching `*.uzleuven.be` **names**
> fall under the `*.uzleuven.*` Tier-3 wildcard, so hostname-based testing of `extranet-2` / `sftp` /
> `prdlbuzldmz02` is in scope — but **direct port-scanning of the unlisted IPs is not** without the
> program's confirmation.

### 8. `extranet-2.uzleuven.be` — second ICS node, **different build** (Tier 3 via `*.uzleuven.*`)

Discovered from the PTR sweep (§7). Same product, same realms, same sign-in URL identifiers — but a
**byte-different software build** and different runtime behaviour from the Tier-1 node.

| Aspect | `extranet` (.120, Tier 1) | `extranet-2` (.114, Tier 3) |
| --- | --- | --- |
| Sign-in UI assets | `bootstrap-3.4.1` / `bootstrap-select-1.13.18` | **`bootstrap-5.3.8`** / `bootstrap-select-1.14.0-beta3` |
| Login-page CSP | none | **`nonce=` on inline `<style>`/`<script>`** ("CSP Compliant") |
| `bootstrap-3.4.1.min.css` | 200 (121 kB) | **404** |
| Landing page (`url_pILuuvz3DlTY4iVo`) | custom 1.3 kB branded page, `<title>Ivanti Connect Secure</title>` | default EUP page 11.2 kB, `<title>Remote access page UZLeuven</title>` |
| `saml-endpoint.cgi?p=sp5` | **500 Internal Error** | **200 — valid SP metadata (1112 B)** |
| `url_default/welcome.cgi` (no cookie) | 200 — renders login form | 302 → `login.cgi?realm=Soft%20Token%20(adfs)` |
| Reason phrases | `302 Found`, `400 Invalid Path` | `302 Moved Temporarily`, `400 Bad Request` |
| Static `Last-Modified` | fixed (`Wed, 07 Jan 2026`) | **per-request "now"** (e.g. `25-Sep-2026 22:41:48`) |
| Realm `Eid - Its Me` via `url_default/login.cgi` | 302 → FAS IdP | `?p=failed` |

Both nodes expose the **same sign-in URL identifiers** (`url_pILuuvz3DlTY4iVo`, `url_4oTd2p4a0itcgdvM`,
`url_ZngUmyh877yGwQwK`, `url_default`) and the same two realms, so this is a **build/config delta
between two nodes of the same gateway**, not a separate deployment. The Tier-1 node runs the **older
UI generation** (Bootstrap 3, no CSP nonce); `extranet-2` runs a newer one (Bootstrap 5, CSP nonces,
functioning SAML metadata endpoint).

**SP metadata recovered from `extranet-2`** (prod 500s on the identical URL):

```xml
<md:EntityDescriptor entityID="https://extranet.uzleuven.be/dana-na/auth/saml-endpoint.cgi?p=sp5">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <!-- 7 NameIDFormat entries: unspecified, emailAddress, X509SubjectName,
         WindowsDomainQualifiedName, kerberos, entity, transient -->
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://extranet.uzleuven.be/dana-na/auth/saml-consumer.cgi" index="1" isDefault="1"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
```

Note it advertises **no `<md:KeyDescriptor>`** (no signing certificate) — consistent with
`AuthnRequestsSigned="false"`. The `entityID`/ACS point at the Tier-1 hostname regardless of which
node you query.

**Build-fingerprint discriminators** (all passive — no explicit version string is exposed):

| Signal | `extranet` (Tier 1) | `extranet-2` | Reading |
| --- | --- | --- | --- |
| `Set-Cookie` on `/` | `SUPPORT_TLS_1_3=0` | absent | cookie was dropped in the newer build |
| `Set-Cookie` on `/` | *(none)* | **`HC_HMAC_VERSION_COOKIE=1`** | **HMAC host-checker cookie hardening present only on ext-2** |
| ICS bundle | `ds_32f43336…js` / `.css` | `ds_350061bb…js` / `.css` | different build token (mutually 404) |
| Bundle content | — | — | the two `ds_*.js` are **byte-identical except the hash they self-reference**; the `ds_*.css` are byte-identical |
| CSP `nonce=` | absent | present on every inline `<style>`/`<script>` | newer template generation |
| Bundled assets | `bootstrap-3.4.1` / `select-1.13.18` | `bootstrap-5.3.8` / `select-1.14.0-beta3` | mutually exclusive → different file sets |
| TLS 1.3 / ALPN | TLS1.3 OK, no `h2` | TLS1.3 OK, no `h2` | *no* discriminator |
| `/dana-na/help/…` | 404 / 400 | 404 / 400 | *no* discriminator |

Because the two `ds_*.js` files are byte-identical apart from the hash they embed, the `ds_<sha256>` name is a
**build fingerprint derived from a build-specific value**, not a content hash — but no reachable file
exposes the underlying ICS version/build string. The RoE's out-of-scope list explicitly covers
"banner grabbing/version disclosure", so an exact version — and therefore a CVE mapping — **cannot be
established passively**.

**Conclusion:** `extranet-2` is demonstrably the **newer build** (Bootstrap 5.3.8, CSP nonces,
`HC_HMAC_VERSION_COOKIE` HMAC hardening, working SAML metadata endpoint). The **Tier-1 `extranet`
runs the older build**, which lacks the HMAC host-checker cookie hardening that the newer node has.
Whether that older build is exposed to any specific pre-auth CVE can only be settled with an active
proof-of-concept — which the RoE requires anyway ("no reports of out-of-date/vulnerable software
without a PoC").

**Patch-state check — CVE-2023-46805 / CVE-2024-21887** (read-only, one GET per row, RoE header present,
`--path-as-is`):

| Request | `extranet` | `extranet-2` |
| --- | --- | --- |
| `GET /api/v1/totp/user-backup-code/../../system/system-information` | **403** (0 B) | **400 Bad Content** (159 B) |
| `GET /api/v1/system/system-information` | 403 (0 B) | 403 (3447 B) |
| `GET /api/v1/foo/bar` (control) | 302 → auth | 302 → auth |

**Both nodes are patched** — the auth-bypass traversal is not honoured anywhere. The nodes reject it
differently (`403` vs `400 Bad Content`), again consistent with different builds. The
memory-corruption pre-auth CVEs (CVE-2025-0282 / CVE-2025-22457) were deliberately **not** probed:
a failed attempt can restart the appliance, and DoS is explicitly out of scope.

**Build hashes** (for correlation against any offline build/CVE database):

```
extranet     ds_32f43336cb252e361c2bb51f0249e7e7db7b4aa114fe964002529bdb7648dc4e.{js,css}
extranet-2   ds_350061bb6df1bc449f1af93b5cdd53eede65154faf760933d473b620b21524a3.{js,css}

sha256(recon/assets/prod_ds.js) = 64656a9ffd23ab4757665dacd5b74e13d892e592387108c43a148f63c4ae8056
sha256(recon/assets/ext2_ds.js) = 8ada528c6f39d8191ba635b30ebcc8e8ea10186f3b50c1d03519130b773abc02
```

**Assessment:** no new exploitable defect — the value is (a) confirmation that two *divergent* ICS
builds front the same VPN, and (b) the recovered SP metadata. A version-specific CVE claim is not
possible passively, and the RoE excludes "software out of date/vulnerable without a PoC".

### 9. Subdomain enumeration — `*.uzleuven.*` (Tier 3 wildcard)

Method: **Certificate Transparency** (`crt.sh` for `%.uzleuven.be` + `%.playuzleuven.be`, 4 698 + 306
certs) → 241 unique names → DNS resolution → RoE scope classification → HTTP fingerprint of every
public in-scope host (one GET each, RoE header present, ≤5 req/s).

```
241 CT names  →  136 resolving  →  106 IN-SCOPE (wildcard T3)
                                   28 NO-BOUNTY  (mir / *dev / *idp* / mijnacc / mirc / …)
                                    2 OUT-OF-SCOPE (jobs, vacatures)
```

Full data: `recon/crtsh_names.txt`, `recon/subdomains_resolved.json`, `recon/subdomain_http.txt`.

**Newly found hosts of interest** (beyond §1–§8):

| Host | IP | Result | Note |
| --- | --- | --- | --- |
| `beeldbank.uzleuven.be` | `195.225.101.70` | 200 **`Microsoft-IIS/10.0`** | image bank — not Cloudflare, not ICS |
| `beeldbank-bo.uzleuven.be` | `195.225.101.70` | 200 IIS, `<title>Picture Pack</title>` | same server |
| `pers.uzleuven.be` | CF `104.20.23.134` | **HTTP 103** (Early Hints) → `UZ Leuven` | personnel/HR portal |
| `mijnplanning.uzleuven.be` | CF | 200 `<title>WorkForce</title>` | workforce planning |
| `histaruz.uzleuven.be` | CloudFront `13.224.95.x` | 302 → `/login/` → `<title>Bynder Brand Portal</title>` | third-party **Bynder** DAM |
| `crl.uzleuven.be` | CF | 200 `<title>UZLeuven CRL Page</title>` | certificate revocation list |
| `awingu.uzleuven.be` + `extranet-awingu`, `fas-awingu`, `firma-awingu`, `horizon-awingu`, `meal-awingu`, `wieiswie-awingu`, `azdsaga-awingu`, `prdcrunner22-awingu` | CF | 200/302 | **Awingu** remote-workspace gateways (8 instances) |
| `vdi`, `wiki`, `webapps`, `gbs`, `ruzb`, `standby`, `extranetmail`, `remote`, `pcrstudioruzb` `.uzleuven.be` | LB `.82` | 302 → `extranet.uzleuven.be/dana-na/auth/saml-sso.cgi?SAMLRequest=…` | internal apps gated by **ICS SSO** on the shared LB |
| `jenkins.gcp`, `tiro-abdo.gcp`, `tiro-uro.gcp` | GCP | 302 → `accounts.google.com/o/oauth2` | Jenkins/RStudio behind Google OAuth |
| `mijnbeleidsinformatie{,-shiny-prd}`, `vbhc{,-mgmt}`, `vpp`, `capaciteitsopvolging` `.…uzleuven.be` | `34.149.5.85` | 302 → **Google IAP** | policy-information apps behind IAP |
| `qr.uzleuven.be` | `54.220.51.86` | 302 → `support.qr-code-generator.com` | delegates to a third-party SaaS |
| `status.uzleuven.be` | CF | 302 → `uzleuven1.statuspage.io` | Statuspage |
| `uzvanelders.uzleuven.be`, `4uz11.uzleuven.be` | CF | 302 → www / extranet | redirectors |
| `sectra-extern`, `vending`, `cll`, `wp5-truststroke`, `random`, `ecrf`, `splunkhf` | CF | 403 / 404 / "Just a moment…" | Cloudflare-fronted (blocked for our IP) |
| `machines` `*.int.gcp.uzleuven.be` (`genai-patientendossier-summarization`, `docuraid-*`, `dermatology-/pediatrie-/traumatology-genai-…`) | **RFC1918 `10.158.x.x`** | unreachable | internal GCP; private IPs are nonetheless published in public DNS |
| `eduroam-radius`, `mx1`, `mx2`, `events`, `extranet-asa`, `extranet-test`, `prddsplunkhf`, `teamssbca/bcp`, `xdshub*` | various | DOWN / filtered | not reachable from this network |

**Takeaways**

- The ICS-SSO pattern is widespread: `pcrstudioruzb`, `vdi`, `wiki`, `gbs`, `ruzb`, `standby`,
  `extranetmail`, `remote` are all fronted by the shared LB at `193.58.149.82` and delegate auth to
  `extranet.uzleuven.be/dana-na/auth/saml-sso.cgi` — i.e. **the ICS gateway is the single SSO chokepoint
  for a large set of internal apps**.
- Four independent edge stacks front the estate: **nginx** (`193.58.149.82`), **Cloudflare**,
  **CloudFront**, and **Google IAP/GCLB**. Only the `193.58.149.x` nginx and IIS hosts are reachable
  without a WAF.
- `beeldbank` (IIS) is the only non-Cloudflare, non-ICS application host with a public origin found so far.
- Several hosts publish **RFC1918 addresses** in public DNS (internal-topology disclosure; minor).

### 10. `beeldbank.uzleuven.be` / `beeldbank-bo.uzleuven.be` — Picture Pack (Tier 3)

Both are **IIS 10.0 / ASP.NET 4.0.30319** on `195.225.101.70` (`x-aspnet-version` disclosed). The
software is the Belgian DAM product **Picture Pack by iMedia bv**, version **3.2.20**.

| Host | Behaviour |
| --- | --- |
| `beeldbank.uzleuven.be` | front-end — **HTTP 200 with a 0-byte body for every path** (`/`, `/index.pp`, `/search.pp`, `/register.pp`, `/misc.pp`, `/downloadsitemap.pp`, `/servemailing.pp`, …); only `/robots.txt` returns content; `/default.aspx` → 404 |
| `beeldbank-bo.uzleuven.be` | **BackOffice** login — `Server: Picture Pack`, `<title>Picture Pack</title>`, footer `Versie: 3.2.20 © 2002 - 2026 iMedia bv` |

- `robots.txt` (front-end) discloses the page set: `downloadsitemap.pp` sitemap, and `Disallow` for
  `misc.pp`, `register.pp`, `search.pp`, `servemailing.pp`.
- Login form → `POST pagelogin.pp` (`loginname`, `password`); password reset → `resetemail`.
- On the BackOffice every `.pp` path returns the login page (auth required; `/register.pp` too).
- Third-party JS/CSS all load from `assets.picturepack.com` (out of scope).

**Tests — all negative:**

| Test | Result |
| --- | --- |
| login with dummy credentials | clean `Inloggen mislukt. …inloggegevens …onjuist` — no stack trace, no SQL error |
| query-string XSS (`?x="><svg/onload=alert(1)>`) | **0** unescaped occurrences |
| password reset with non-existent address + XSS payload | generic *"Als het emailadres bij ons bekend is…"* → **no user enumeration**, **0** reflections |
| front-end repeated with a session cookie | still 200 / 0 bytes |

**No exploitable defect found.** The version banner (`3.2.20`) is out of scope (RoE excludes version
disclosure), and the reset response is deliberately non-enumerating.

### 11. ICS as SAML **IdP** — `/dana-na/auth/saml-sso.cgi` and the internal SPs (Tier 3)

The subdomain sweep (§9) showed `vdi`, `wiki`, `gbs`, `ruzb`, `standby`, `remote`, `extranetmail`,
`pcrstudioruzb` all bouncing to the ICS. They are **Shibboleth SPs**:

| | |
| --- | --- |
| Issuer / entityID | `https://<host>.uzleuven.be/shibboleth` |
| ACS | `https://<host>.uzleuven.be/Shibboleth.sso/SAML2/POST` |
| `AuthnRequestsSigned` | `1` (requests signed — `SigAlg` present in the redirect) |
| Assertions | **encrypted** (`EncryptionMethod` list: aes128/192/256-gcm, aes*-cbc, 3des-cbc, rsa-oaep) |
| SP metadata | public at `/Shibboleth.sso/Metadata` (200, ~6.5–9.6 kB each) |

So **Ivanti Connect Secure is acting as the SAML IdP** for this app set —
`extranet.uzleuven.be/dana-na/auth/saml-sso.cgi` is the IdP endpoint.

**The `/old` finding resolved.** Following the SP-initiated flow end-to-end:

```
vdi.uzleuven.be/                      302 → extranet.uzleuven.be/dana-na/auth/saml-sso.cgi?SAMLRequest=…&SigAlg=…
  saml-sso.cgi                        302 → https://extranet.uzleuven.be/old/
      (Set-Cookie: DSSAMLLOGINFLOW=1; DSAUTHASSERTREF=<32 hex>; DSSAMLSSONONSAMLHOSTNAME=0; DSSignInURL=/old/)
  /old/                               302 → /dana-na/auth/url_default/welcome.cgi
  url_default/welcome.cgi             200 → legacy sign-in page
```

`/old` is therefore **not a vestigial page**: it is the landing page hard-wired into the live
SAML SSO flow for every internal SP. The admins commented the link out of the branded landing page
(§1) but the IdP still routes users through the legacy `url_default` sign-in. That explains both the
original commented-out link and why the legacy realm-picker page is reachable.

**`saml-sso.cgi` hardening tests — all negative:**

| Test | Result |
| --- | --- |
| no params / blank / invalid base64 `SAMLRequest` | 200 + error page `Details: Invalid SAML Authentication request. (Base64 decode … failed!)` |
| reflected XSS via `SAMLRequest` / `RelayState` | **0** unescaped payloads |
| client-supplied `DSSAMLLOGINFLOW` / `DSAUTHASSERTREF` cookies | endpoint **clears** them (`expires=01 Jan 1970`) and returns 200 — no flow hijack |
| arbitrary `RelayState=https://evil.example/` | not reflected in the response |

No exploitable defect: the IdP validates the request, does not reflect input, and resets its own
flow cookies. The error text is verbose but contains no sensitive data.

### 12. Awingu / Parallels Secure Workspace instances (Tier 3) — unauthenticated API surface

Nine hosts serve the same Angular SPA behind Cloudflare:
`awingu`, `extranet-awingu`, `fas-awingu`, `firma-awingu`, `horizon-awingu`, `meal-awingu`,
`wieiswie-awingu`, `azdsaga-awingu`, `prdcrunner22-awingu` `.uzleuven.be`.
Backend is **Awingu 5.7.1** (now Parallels Secure Workspace; Django REST Framework backend).

| Endpoint | Auth | Result |
| --- | --- | --- |
| `/api/v2/` | **none** | 200 — DRF **API root**, enumerates **50 endpoints** |
| `/api/v2/docs/`, `/api/docs/` | **none** | 200 — **full ReDoc documentation: 2.67 MB, 163 paths** |
| `/api/v2/` (`Accept: text/html`) | **none** | 200 — DRF **browsable API** enabled |
| `/api/v2/configuration-info/` | **none** | 200 — `version: **5.7.1**`, `license.customer: **UZL-2024**` |
| `/api/v2/branding/` | **none** | 200 — `domain_name: UZLEUVEN`, internal `domains/2`, `branding-images/4`, `is_sso_enabled: false` |
| `/api/v2/sessions/` (GET) | **none** | 200 — empty list for anonymous (POST is the login endpoint; requires `username`) |
| every other path (from the 50- and 163-path sets) | required | 401 `Authentication credentials were not provided` |

**The docs disclose the administrative/operational API**, e.g. `actions/reboot-appliances/`,
`actions/shutdown-appliances/`, `actions/ldapsearch/`, `actions/tcpscan/`, `actions/udpscan/`,
`actions/traceroute/`, `actions/environment-backup-create|list|restore/`,
`configuration/generate-intervention-password/`, `configuration/decode-license/`,
`get-certificate-content/`, `ssl-offloader-certificates/`.

**Verified not-exposed:** every one of those was probed with `OPTIONS` (metadata-only — no action
invoked) and returned **401**: `ping`, `uptime`, `ip-address-appliances`, `ldapsearch`, `check-license`,
`client-ip`, `generate-intervention-password`, `system-message`, `get-certificate-content`, `versions`,
`features`, `domains`, `sessions/generate-token`, `user-count`, `validators`. So there is **no
unauthenticated data or action endpoint** beyond the three information endpoints above.

**Session-injection / fixation check — negative.** `POST /api/v2/sessions/` is the login endpoint; the
decoded CoreAPI schema (at the equally-unauthenticated `/api/v2/docs/schema.js`) gives its contract:

```
sessions.create = POST /api/v2/sessions/
  required : username
  optional : password, domain, fingerprint, is_trusted, twofactor, new_password,
             privacy_policy_accepted, login_without_admin_rights, force_mfa_login, logout_other_sessions
```

`password` is **not** required and `fingerprint` / `is_trusted` are accepted — this is the device-trust
login call. Tests (using a non-existent account):

| Test | Result |
| --- | --- |
| `POST sessions/ {}` | 400 `{"username": ["This field is required."]}` |
| `POST sessions/ {username}` — **no password** | **401** `AUTHENTICATION_FAILED / PRE_AUTH_REQUIRED` |
| `POST sessions/ {username, password:"x"}` | **401** — byte-identical response |
| `GET sessions/1/`, `sessions/2/` | **404** — queryset is user-scoped → no IDOR |
| `GET sessions/current/`, `current-light/` | 401 |
| `POST sessions/heartbeat/`, `generate-token/`, `disable-token/` | **401** |

So **no session can be created, read or injected without authentication**, and because the create
contract exposes no client-supplied session id/token, **fixation is not possible** either — the server
issues the session. Two informational residues: the 401 body reflects the submitted `username` and
leaks internal codes (`AUTHENTICATION_FAILED` / `PRE_AUTH_REQUIRED`); and it is *identical* for
existing and non-existent accounts, so there is no user enumeration. A username containing an XSS
payload was rejected by Cloudflare's WAF ("Just a moment…").

**CVE mapping — none.** The NVD 2.0 API returns **zero** results for `Awingu` and for
`Parallels Secure Workspace`; a control query for `Pulse Secure` returned 110 hits and
`Ivanti Connect Secure` 71, so the API itself is working. Sweeping all 161 `Parallels` CVEs found
**none** mentioning Awingu or Secure Workspace. The vendor advisory pages are not machine-readable.

Therefore **Awingu 5.7.1 maps to no known CVE**, so this finding's severity is *not* elevated by a
known vulnerability and rests entirely on the information disclosure above (Low).

**The remaining `*-awingu` hosts are app launchers, not separate instances.** `azdsaga`, `horizon`,
`meal` and `wieiswie` `-awingu.uzleuven.be` redirect *every* path to a **published-app launch URL** on
the same deployment:

```
horizon-awingu   → https://extranet-awingu.uzleuven.be/api/http/apps/04358104-9fee-4e45-a292-52963fee98a7?path=%2F
meal-awingu      → https://extranet-awingu.uzleuven.be/api/http/apps/6805eeee-26f9-42e1-a704-35b0150e7b0f?path=%2F
wieiswie-awingu  → https://extranet-awingu.uzleuven.be/api/http/apps/1dc78c2d-c7ad-4c1d-b6ec-5085036dfdea?path=%2F
azdsaga-awingu   → https://azdsaga-awingu.uzleuven.be/api/http/apps/dbc6f81d-7240-4c54-9058-efc7efec44ff?path=%2F
```

Following any of them unauthenticated yields `302 → /login?next=…`, i.e. **the launch endpoints require
authentication**, so these aliases expose neither extra API surface nor unauthenticated app access. The
only by-product is four published-app UUIDs, which are not secret beyond the alias hostnames themselves.

**Assessment — Low (information disclosure).** Unauthenticated API enumeration, complete API
documentation, the DRF browsable API, and product-version (`5.7.1`) + licence-customer disclosure.
Enables precise CVE targeting and maps the admin API, but grants no unauthenticated access to data or
actions. (A bare version banner is out of scope; the *enumeration + documentation* exposure is the
reportable element.)

### 13. `www.uzleuven.be` / `uzleuven.be` (Tier 1) and remaining reachable hosts

`www.uzleuven.be` and the apex `uzleuven.be` serve the same **Drupal** site on **CloudFront + Caddy**
plus a custom "wm" cache layer (`x-wm-cache`, `wm-s-maxage`), multilingual (`/nl`, `/en`). A WAF
returns a distinctive `403 <html>BLOCKED ED2024PTO17</html>` for some paths.

| Path | Result |
| --- | --- |
| `/robots.txt`, `/sitemap.xml` | 200 — Drupal defaults; `sitemap.xml` is the **Simple XML Sitemap** module |
| `/core/CHANGELOG.txt`, `/CHANGELOG.txt` | **403** (version hidden) |
| `/user/password`, `/user/1`, `/admin`, `/nl/admin` | 403 (Drupal) |
| `/nl/user/register`, `/nl/user/password` | 403 (Drupal) |
| `/jsonapi`, `/jsonapi/`, `/jsonapi/user/user` | 404 — **JSON:API disabled** |
| `/update.php`, `/core/install.php`, `/index.php` | **403 `BLOCKED ED2024PTO17`** (WAF) |
| `/sites/default/files/`, `/core/`, `/profiles/` | 404 |

**CloudFront → S3 misroute.** `/user/login`, `/user/register` and `/nl/user/login` are answered by an
**S3 origin**, not Drupal:

```xml
HTTP/2 404 · server: AmazonS3 · content-type: application/xml
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message>
<Key>user/login</Key><RequestId>0MKQ2TN6N7XXB4M9</RequestId>…</Error>
```

i.e. Drupal's login/registration routes are shadowed by an S3 bucket for those path patterns — while
`/en/user/login` *does* reach Drupal (403). The routing is therefore inconsistent per language prefix.
Impact is **low**: the bucket name is not disclosed, no object is retrievable (only `NoSuchKey`), and
it merely reveals that an S3 origin exists behind the distribution.

**Other reachable hosts**

| Host | Result |
| --- | --- |
| `crl.uzleuven.be` | 200 Cloudflare — "UZLeuven CRL Page", `robots.txt: Disallow: /` |
| `qr.uzleuven.be` | 200 — delegates to the third-party `support.qr-code-generator.com` |
| `wmimages.uzleuven.be` | 400 (needs a concrete path; image CDN) |
| `assets.uzleuven.be`, `stats`, `events`, `media-acc` `.uzleuven.be` | unreachable from this network |

**Assessment — no exploitable defect.** Drupal version is hidden, JSON:API is off, user/admin routes
are 403, and the WAF blocks the classic probe paths. The S3 misroute is a cache-behaviour
misconfiguration with no demonstrated impact.

## Reportability (RoE filter)

Applying the RoE's **out-of-scope** list to the two candidates recorded above:

| Item | Verdict | Basis |
| --- | --- | --- |
| §2 ADFS IdP-initiated sign-on / RP enumeration | **Informational — probably not eligible** | *"Verbose messages/files/directory listings without disclosing any sensitive information"* and *"Theoretical security issues with no realistic exploit scenario(s) or attack surfaces"*. No exploit was demonstrated: the impact depends on an RP accepting **unsolicited** assertions, which cannot be established without credentials. |
| §12 Awingu `version: 5.7.1` | **Explicitly excluded** | *"Banner grabbing/Version disclosure"*. |
| §12 Awingu API root / docs / browsable API | **Informational — probably not eligible** | *"Verbose messages/files/directory listings without disclosing any sensitive information"*. Decisively, **every** action and data path was proven **401**, which removes the impact argument entirely — leaving a hardening observation, not a vulnerability. |

The program states it is *"specifically looking for: leaking of personal and medical data, administrative
access, …"*. **Neither candidate does either.**

The only arguable lift for §2 is that the RP list discloses **internal hostnames** and **security
tooling** (`InsightVM`, `SentinelOne`, `Wallarm`, `Patch Manager Plus`, `isor`, `ipam`) — more than mere
app names, and therefore arguable as "sensitive information". Even so, with no demonstrated exploit it
still reads as informational.

**Conclusion — no confident bounty-eligible finding in this engagement so far.** Both candidates are
recorded as hardening/context observations rather than submissions. The bounty-relevant surface
(`ecrf.uzleuven.be`, `sectra-extern.uzleuven.be`, …) is still untested because Cloudflare blocks the
testing source IP (§3, §6).

## Artifacts

| File | Contents |
| --- | --- |
| `extranet.uzleuven.be` | original Burp export supplied with the engagement |
| `recon/02_old_welcome.html` | live legacy `url_default` sign-in page |
| `recon/03_url_admin.html` | `url_admin` "no permission" page |
| `recon/04_fedmetadata.xml` | ADFS federation metadata |
| `recon/05_idpinitiatedsignon.html` | IdP-initiated sign-on page + 55 RP names |
| `recon/06_liquidfiles_home.html`, `recon/07_liquidfiles_help.html` | LiquidFiles home / help |
| `recon/08_owa_logon.html` | OWA logon page (Exchange `15.2.2562`) |
| `recon/09_ext2_landing.html`, `recon/11_ext2_urldefault_welcome.html` | `extranet-2` landing / legacy pages |
| `recon/10_ext2_saml_endpoint_sp5.txt` | SP metadata recovered from `extranet-2` |
| `recon/diff_extranet.uzleuven.be.txt`, `recon/diff_extranet-2.uzleuven.be.txt` | per-endpoint fingerprints used for the node diff (§8) |
| `recon/assets/` | ICS bundles + error pages from both nodes (build hashes) |
| `recon/crtsh_names.txt`, `recon/subdomains_resolved.json`, `recon/subdomain_http.txt` | subdomain enumeration + resolution + HTTP fingerprint (§9) |
| `recon/bl_beeldbank*.html` | Picture Pack front-end / BackOffice pages (§10) |
| `recon/sp_vdi_metadata.xml` | Shibboleth SP metadata (`vdi`) (§11) |
| `recon/awingu_api_root.json`, `recon/awingu_api_paths.txt`, `recon/awingu_api_docs.html`, `recon/awingu_api_probe.txt` | Awingu unauthenticated API surface (§12) |
| `recon/awingu_schema.js`, `recon/awingu_schema.json` | decoded CoreAPI schema (session/login contract) |
| `recon/www_home.html` | Drupal front page of `www.uzleuven.be` (§13) |
| `runs/2026-09-25_22-27-18/` | sirius masscan + nmap run over the RoE IP range |

## Next

- **Do not spend submissions on §2 / §12 as "vulnerabilities"** — under this RoE they are
  Informational at best (see *Reportability (RoE filter)*). Keep them as context.
- **Ask the program to allow-list the testing source IP** — this is the only route to the surface the
  program actually pays for (medical data / admin access): `ecrf.uzleuven.be`,
  `sectra-extern.uzleuven.be`, and the other Cloudflare-fronted hosts (`w1`, `random`,
  `wp5-truststroke`, `prddsplunkhf`, `mijnplanning`, `pers`, `vending`).
- Test-with-credentials backlog (only with a valid account / signing oracle): whether an RP accepts
  **unsolicited** SAML assertions (the difference between Informational and a real finding for §2),
  LiquidFiles `ruby-saml` XSW / parser-differential CVEs (§4), ICS assertion handling via
  `saml-sso.cgi` (§11), and the authenticated Awingu API (§12).

## Change log

- 2026-09-26 — reportability review against the RoE exclusion list: both candidates are **Informational
  at best**; added *Reportability (RoE filter)*, removed the "reportable" framing from `Next`.
- 2026-09-25 — initial recon from the supplied Burp export (`/old`, ICS, ADFS); host sweep;
  sirius scan ingested.
- 2026-09-25 — Exchange/LB/mail hosts mapped; passive PTR sweep of `193.58.149.0/24`; `extranet-2`
  found; two-node build diff; ICS build hashes captured; CVE-2023-46805 patch-state check (patched).
- 2026-09-25 — subdomain enumeration via CT logs (§9): 241 names → 106 in-scope; HTTP fingerprint
  of all public in-scope hosts; new edge stacks (IIS `beeldbank`, Awingu, Google IAP, CloudFront)
  mapped.
- 2026-09-25 — `beeldbank` Picture Pack front-end/BackOffice assessed (§10): no exploitable defect.
- 2026-09-25 — ICS SAML-IdP path mapped (§11): 8 Shibboleth SPs federate to `saml-sso.cgi`, and the
  SP-initiated flow lands on **`/old`** — resolving the original lead.
- 2026-09-25 — Awingu estate assessed (§12): unauthenticated DRF API root, full API docs (163 paths),
  browsable API, version 5.7.1 + licence disclosure. All action/data endpoints verified 401.
  Session-injection checked and ruled out. NVD/vendor check: **no CVE maps to Awingu 5.7.1**.
- 2026-09-25 — `www.uzleuven.be` / apex assessed (§13): Drupal behind CloudFront+Caddy+WAF, version
  hidden, JSON:API off, `/user/*` misrouted to an S3 origin. No exploitable defect.
- 2026-09-25 — remaining `*-awingu` hosts confirmed to be per-app launchers for the same 5.7.1
  deployment; launch endpoints require auth (302 → `/login?next=…`).
