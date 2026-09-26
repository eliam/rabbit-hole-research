# Nexuzhealth Web PACS (UZ Leuven) — Intigriti engagement notes

Running notes for the **UZ Leuven / Nexuzhealth Web PACS** program on Intigriti
(Public / Open, Hospitals & Healthcare). Reference: `nexuzhealthwebpacs.RoE`.
All testing stayed within the published RoE.

Patient access to radiology images (PACS). Patients log in with a **date of
birth + a unique code** issued by the physician; the code grants access to one
study. Both in-scope assets are **Tier 2** (bounties up to €1,000).

**Outcome: no confirmed vulnerability.** The in-scope pre-auth surface was
enumerated and audited in depth; everything found is hardening-tier and most of
it looks RoE-ineligible. The single biggest constraint is that the two
documented test accounts do not work, which locked us out of the post-auth
surface — where this program's real payouts live.

---

## Rules of engagement (observed)

- **Automated tooling: max. 5 requests / second** — never exceeded. Most probes
  ran at ~3–4 req/s with explicit sleeps between requests.
- **User agent: "Not applicable"** and **Request header: "Not applicable"** in
  the RoE panel — so no custom UA and no mandatory header were used.
  ⚠️ See *Housekeeping* below: the sibling `uzleuven` program from the **same
  organisation** mandates `X-Intigriti-Username: eliam`, so this discrepancy is
  worth confirming before any resumed testing.
- **No DoS/DDoS, no brute force.** No credential guessing against `uzContact`,
  `admin`, or anywhere else.
- **Do not guess patient codes** — the RoE states usernames auto-lock. Payload
  strings were never used to fish for valid codes.
- **Safe harbour applies.** Third-party closed-source components are involved,
  so some issues may be unfixable in-house.
- RoE interest areas: privilege escalation, XSS (no self-XSS, latest browsers
  only), RCE, SQLi.

### Provided test accounts — both non-functional

| Account | Code | Date of birth | Observed |
| --- | --- | --- | --- |
| Patient 1 | `e3Dgin2r` | 05/09/1967 | HTTP 500 + generic auth error |
| Patient 2 | `mcuk7jp4` | 01/05/1967 | HTTP 500 + generic auth error |

Reproduced independently by the operator. `POST` to
`/simplesaml/module.php/uzContact/uzContact.php` returns **HTTP 500** with a
re-rendered form carrying the generic i18n string
`contact.default` = *"Something went wrong during authentication!"*. A `POST`
with **no** credential fields returns **200** with the plain form, so the 500 is
input-dependent — i.e. the credential check runs and rejects. The response is
byte-identical (9821 bytes) for both accounts, so it is a uniform failure and
not a parsing error.

> Consequence: the entire authenticated surface (the study viewer, `/dicom/`,
  any per-study object references) was **unreachable**. This is the recommended
  starting point if the engagement is resumed.

---

## Scope

| Tier | Asset | Notes |
| --- | --- | --- |
| Tier 2 | `idp-contact.nexuzhealth.be` | SimpleSAMLphp **IdP** |
| Tier 2 | `media.nexuzhealth.be/patient/` | patient portal (**SP**) |

**Everything else is out of scope** — the RoE is explicit: *"Any area that is
not explicitly listed in the section above is out of scope."* This includes the
`/dicom/` path on the same host (physician viewer, different federation), and
all sibling hosts such as `idp-contact-play`, `media-acc`, `html5viewer`,
`mynexuz*`, `forms.nexuzhealth.be`.

### Scope discipline note

Early on, passive third-party enumeration (`subfinder`, `crt.sh`) was run
against `nexuzhealth.be` and produced ~67 hostnames. **This was scope creep and
was dropped.** No packet was ever sent to any of those hosts, and none of the
results fed into testing. It is recorded here only so the mistake is not
repeated: for a two-URL scope, subdomain enumeration adds nothing. The listed
hosts are treated as *do-not-touch*.

---

## Environment / architecture

Both in-scope hosts are fronted by **Cloudflare** (`104.18.26.241`,
`104.18.27.241`) behind a Google Trust Services wildcard certificate
(`CN=nexuzhealth.be`, SAN `nexuzhealth.be` + `*.nexuzhealth.be`, valid
2026-09-16 → 2026-12-15). Because everything resolves to Cloudflare anycast,
**port scanning was deliberately not performed** — it would have targeted
Cloudflare infrastructure, not the client.

Two distinct federations were identified:

| Path | Federation | Identity source |
| --- | --- | --- |
| `media.nexuzhealth.be/patient/` | **SimpleSAMLphp IdP** on `idp-contact` | code + date of birth (custom `uzContact` module) |
| `media.nexuzhealth.be/dicom/` | **Shibboleth SP** + Belgian eID | `idp.iamfas.belgium.be/fas` (Fedict FAS: `eid`, `totp`, `bmid`) |

The `media` host runs a Shibboleth SP that federates with the in-scope
SimpleSAMLphp IdP. A real AuthnRequest captured from `/patient/` decodes to
(`recon/authnrequest-decoded.xml`):

```xml
<samlp:AuthnRequest
  AssertionConsumerServiceURL="https://media.nexuzhealth.be/patient/Shibboleth.sso/SAML2/POST"
  Destination="https://idp-contact.nexuzhealth.be/simplesaml/saml2/idp/SSOService.php"
  ForceAuthn="1" ProtocolBinding="...HTTP-POST" Version="2.0">
  <saml:Issuer>https://media.nexuzhealth.be/patient</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate="1"/>
</samlp:AuthnRequest>
```

The IdP advertises three auth sources to unauthenticated users via the test
page: **`admin`**, **`uzContact`**, **`default-sp`**. Its `DiscoFeed` lists four
entities: the in-scope IdP, `idp.iamfas.belgium.be/fas`, `idp-cookie`, and
`idp-token-nexuzhealth`.

### Endpoint behaviour cheatsheet

| Response | Meaning |
| --- | --- |
| `error code: 502` (16 B, `text/plain`) | SimpleSAMLphp module router miss **or** an erroring module route — **indistinguishable** from outside |
| `File not found.` (16 B) | file genuinely absent from the docroot |
| `403` (548 B) | Cloudflare/edge rule or directory listing denied |
| `404` (548 B) | nginx-level 404 (e.g. directory does not exist) |

Reachable pre-auth endpoints: `core/authenticate.php`, `core/no_cookie.php`,
`core/errorreport.php`, `core/as_login.php`, `core/loginuserpass.php`,
`core/show_metadata.php`, `core/cleardiscochoices.php`, `core/frontpage_*.php`,
`core/idp/logout-iframe.js`, `core/assets/js/loginuserpass.js`,
`logout.php`, `saml2/idp/{metadata.php,SSOService.php,SingleLogoutService.php}`,
`uzContact/{uzContact.php,js/*,css/*,img/*,locales/*}`.

---

## Findings

Nothing below survived the RoE filter as a submittable vulnerability. They are
recorded as (a) hardening observations, (b) a **central audit result** that
future testers should not have to re-derive, and (c) negative results with
evidence.

### 1. IdP SAML certificate — self-signed, `CA:TRUE`, 9-year validity, signing+encryption key reuse

Tier 2 · `idp-contact.nexuzhealth.be` · **hardening** (probably not reportable)

From `/simplesaml/saml2/idp/metadata.php` (`recon/idp-metadata.xml`):

- Subject `CN=idp-prod`, `O=UZ Leuven`, email `netadmin@uzleuven.be`.
- **Self-signed** with `Basic Constraints: CA:TRUE`.
- Validity **2017-09-26 → 2027-09-26** — a single ~9-year key.
- The **same certificate** is published for both `use="signing"` **and**
  `use="encryption"`.

Signing/encryption key reuse is poor crypto hygiene: the key that authenticates
assertions is also the key that decrypts inbound material. Exploitation requires
private-key compromise, so there is no remotely demonstrable impact from the
outside. Reportable at best as a low-severity hygiene item.

### 2. SimpleSAMLphp 1.17.x (EOL) — CVE-2019-3465 assessed **not exploitable**

Tier 2 · `idp-contact.nexuzhealth.be` · **hardening** (RoE-ineligible as-is)

The IdP was fingerprinted to **SimpleSAMLphp 1.17.x**, bounded **1.17.0 – 1.17.8**
without cloning anything. Method and evidence:

| # | Observable | Upstream match | Bound |
| --- | --- | --- | --- |
| A | `/simplesaml/resources/script.js` = 789 B, sha256 `a77328fd…` | 1.17.0 – 1.18.4 (801 B from 1.18.5) | ≤ 1.18.4 |
| B | `/simplesaml/resources/default.css` = 7820 B, sha256 `2b4b4a2a…` | 1.17.0 – 1.19.0 (7905 B from 1.19.1) | ≤ 1.19.0 |
| C | `/simplesaml/authmemcookie.php` present | file **removed** in 1.18.0 | ≤ 1.17.x |
| D | login page contains `<input id="processing_trans">` | only in `modules/core/templates/loginuserpass.php` (1.17.x); 1.18.0 replaced it with Twig | 1.17.x |

`processing_trans` is the decisive marker — verified absent from the JS asset in
every version, so it can only have come from the 1.17 PHP template.

**Could not narrow to a patch level:** every web-facing static asset is
byte-identical across 1.17.0–1.17.8, and the module router returns an
indistinguishable `502` for all missing/erroring routes. A version oracle via
`Template::asset()` (`?tag=<md5(version)[0:5]>`) was investigated and is
**closed** — this deployment never emits it. A version bump in
`Configuration::getVersion()` is only rendered by the admin UI.

**Relevant advisories:**

| Advisory | Severity | Affects | Fixed |
| --- | --- | --- | --- |
| SSPSA 201911-01 / **CVE-2019-3465** — signature validation bypass | Critical | ≤ 1.17.6 | 1.17.7 |
| SSPSA 201911-02 — unauth `phpinfo()` in experimental admin module | Low | 1.17.0 – 1.17.7 | 1.17.8 |

Source diffing (1.17.6 / 1.17.7 / 1.17.8, all 1326 files) shows the
CVE-2019-3465 fix is a **vendored dependency bump** — `robrichards/xmlseclibs`
3.0.3 → 3.0.4 and `simplesamlphp/saml2` 3.4.1 → 3.4.2 — plus a version-string
change. It is therefore **not remotely detectable**.

**Why it is not exploitable here.** The vulnerable code sits in the xmlseclibs
XML-DSig (XPath) path. Validation is gated in
`modules/saml/lib/Message.php:239-268` by `validate.authnrequest` /
`validate.logout` / `redirect.validate`, read from SP metadata then IdP
metadata, **defaulting to false**; the target's IdP metadata carries no
`sign.authnrequest` and no `redirect.sign`. AuthnRequests arrive on the
**HTTP-Redirect binding**, whose signatures are verified via
`XMLSecurityKey`/OpenSSL in `checkSign()`, never reaching the XML-DSig code.
The `admin` module is also not routed (every `/admin/*` → 502), so SSPSA
201911-02 is moot.

Note the RoE filter: *"Reports that state that software is out of date/vulnerable
without a proof-of-concept"* are not eligible, and 1.17.x is EOL. On its own this
is a lead, not a submission.

### 3. AuthnRequest signature validation is **not enforced** — assessed not exploitable

Tier 2 · `idp-contact.nexuzhealth.be` · **not a vulnerability**

Proven empirically rather than inferred. A fresh, genuinely signed AuthnRequest
was captured from the in-scope SP and replayed to `SSOService.php` in four
variants (`recon/var_*.txt`, `recon/h_*.txt`):

| Variant | Content | Result |
| --- | --- | --- |
| `full` | SAMLRequest + RelayState + SigAlg + Signature | **302** → `uzContact.php` |
| `nosig` | signature stripped entirely | **302** → `uzContact.php` |
| `badsig` | Signature first char corrupted | **302** → `uzContact.php` |
| `tampered` | payload modified, original signature kept | **302** → `uzContact.php` |

All four were accepted, so `Message::validateMessage()` is returning early.

This is **not** a finding, for three independently verified reasons:

1. Unsigned AuthnRequests are permitted by the SAML specification — accepting
   them is a normal configuration choice.
2. **No ACS hijack.** `getAssertionConsumerService()`
   (`modules/saml/lib/IdP/SAML2.php:171-247`) only ever returns endpoints
   already present in the IdP's *own* `saml20-sp-remote` metadata. An
   attacker-supplied `AssertionConsumerServiceURL` is skipped and the
   configured default is used, with a warning logged.
3. The `<saml:Issuer>` must resolve to a configured SP or
   `getMetaDataConfig()` throws — so arbitrary SPs cannot be impersonated.

Together these mean an attacker cannot redirect an assertion. This result also
independently confirms §2's conclusion that CVE-2019-3465 is unreachable.

### 4. `core/authenticate.php` test endpoint exposed pre-auth

Tier 2 · `idp-contact.nexuzhealth.be` · **low, likely RoE-ineligible**

`/simplesaml/module.php/core/authenticate.php` returns **200** to unauthenticated
users and is SimpleSAMLphp's *"Test authentication sources"* page. It discloses
the configured auth sources (`admin`, `uzContact`, `default-sp`) and provides
`?as=` links that initiate login for any of them, plus a `?language=` switcher.

Impact is disclosure-only: the auth-source names are not sensitive secrets, and
the actual credential handling is unaffected. `?as=default-sp` throws an
uncaught exception (`{\SimpleSAML\Auth\State_…exceptionId=…}` in the URL)
resolving to **HTTP 500 with an empty body** — no stack trace, path, or version
leak. `?as=admin` reaches a standard password form.

RoE relevance: *"Verbose messages/files/directory listings without disclosing any
sensitive information"* is out of scope, which probably covers this. SimpleSAMLphp
guidance is nonetheless to disable `core:authenticate` in production.

### 5. Shared docroot between the two in-scope hosts — informational

`/shibboleth-embedded-ds-1.0.2/` (on `media`) and
`/simplesaml/module.php/uzContact/` (on `idp-contact`) serve **byte-identical**
content — same `locales/*/translation.json`, same `js/handlebars.js`, same
`img/logo-contact.png` (28480 B, matching sha). `/simplesaml/module.php/uzContact/`
returns the EDS page (md5 `19799bef…`), identical to `ds.html`.

So the `uzContact` "module" is really the same directory as the EDS static site,
exposed under two URL prefixes across two hostnames. Interesting architecturally,
not remotely exploitable on its own. Both are within scope.

### 6. Cloudflare WAF — informational

The edge runs a managed WAF that returns **403** for SQL-ish payloads (`-- `,
`' OR '1'='1`, `'AND'`, `'||'`) in POST bodies, and issues a managed challenge
(`cf_chl_opt`) for `<script>` in query strings. This materially limits
injection testing (see §"Not testable").

### 7. `admin` auth source — no default-credential bypass

`core:AdminPassword` (`modules/core/lib/Auth/Source/AdminPassword.php`) forces
the username to `admin`, and **refuses to authenticate at all** while
`auth.adminpassword` is still the default `123` — it throws `Error('NOTSET')`.
Comparison goes through `Crypto::pwValid()`. No default credentials to test, and
brute force is prohibited by the RoE.

---

## Tested and found clean (the bulk of the work)

Every reachable pre-auth endpoint was read from upstream source *and* exercised
live. All correctly defended:

| Endpoint | Control |
| --- | --- |
| `www/logout.php` | `link_href` → `HTTP::checkURLAllowed()`; `link_text` → `htmlspecialchars()` — no XSS, no open redirect |
| `www/errorreport.php` | `$email` rejected if it contains `\s` (**blocks CRLF header injection**); `$text` → `htmlspecialchars()` |
| `www/saml2/idp/metadata.php` | `output=xhtml` → `htmlspecialchars()`; `idpentityid` must resolve to configured metadata or it throws |
| `www/saml2/idp/SSOService.php` / `SingleLogoutService.php` | thin wrappers; `ReturnTo` → `checkURLAllowed()` |
| `modules/core/www/as_login.php` | `ReturnTo` → `checkURLAllowed()` |
| `modules/core/www/cleardiscochoices.php` | `ReturnTo` → `checkURLAllowed()`; cookie loop only touches the requester's own cookies |
| `modules/core/www/show_metadata.php` | `Auth::requireAdmin()` runs first (live: 302 to admin login) |
| `modules/core/www/authenticate.php` | no direct vuln (exposure noted in §4) |
| `modules/core/lib/Auth/Source/AdminPassword.php` | default-password guard (§7) |

Other verified negatives:

- **Open-redirect whitelist enforced.** `as_login.php?AuthId=uzContact&ReturnTo=https://example.com/`
  → **502** (rejected). `ReturnTo` pointing at the in-scope hosts, or relative
  (`/simplesaml/`), → **302** (allowed).
- **No XSS via `authenticate.php?ReturnTo`.** The value is reflected inside an
  `href` attribute in the language bar, but it is URL-encoded before insertion
  and the attribute is HTML-escaped — verified `%22`, `%3C`, `%3E`, `%26`, `%2F`
  all emerge encoded, and `&` as `&amp;`.
- **Discovery-service `redirect()` is hardened.** The EDS `redirect()` gates on
  `isAllowedUrl()`, which requires `https:` and a hostname that equals or is a
  subdomain of an explicit allowlist (`mynexuz.be`, `uzleuven.be`,
  `uz.kuleuven.ac.be`, `nexuzhealth.{net,be,com}`, `mynexuz*`). No open redirect.
- **No CORS misconfiguration.** No `Access-Control-Allow-Origin` on `Origin:`
  probes; `OPTIONS /` returns a bare `405`.
- **`expose_php` is off** — no `X-Powered-By`, no server version.
- **`showerrors` is off** — error pages carry no stack traces, file paths, or
  version strings. `SSOService.php` with garbage input → 500 with a themed page.
- **No sensitive files exposed.** Swept the `uzContact` module dir for
  `.htaccess`, `.git/config`, `config.php`, `composer.json`, `.bak`/`~`,
  `*.log`, `vendor/`, `Dockerfile`, `.DS_Store` — all 502/404.
- **Client-side libraries are current**: Handlebars **4.7.8** (patched),
  jQuery **3.7.1**, moment 2.30.1, validator.js 13.12.0. Only i18next 1.11.2 and
  Bootstrap 4.0.0-alpha.6 are old, and neither is reachable as a vector here.
- **Template injection ruled out.** The login/EDS pages use Handlebars
  triple-stache (`{{{resources.*}}}`) but `resources` comes from server-side
  `translation.json` files, never from request input. The one attacker-reachable
  interpolation, `value="{{code}}"`, is double-stache (escaped).
- **Dangerous-pattern sweep** over `lib/`, `modules/`, `www/` (excluding
  `vendor/` and tests): **zero** hits for `eval(`, `unserialize(`, `extract(`,
  `create_function`, `preg_replace` `/e`.

---

## Not testable / blocked

### SQLi in the `uzContact` credential lookup — inconclusive

The only place with real server-side logic pre-auth. Result matrix (`POST` to
`uzContact.php` with a fresh `AuthState` each time):

| Payload | Result |
| --- | --- |
| baseline, valid creds | 500, 9821 B |
| `username=e3Dgin2r'` | 500, **9821 B** (identical) |
| `birthdate=05/09/1967'` | 500, **9821 B** (identical) |
| `username=e3Dgin2r\` | 500, **9821 B** (identical) |
| `username=e3Dgin2r'-- -` | **403 — Cloudflare WAF** |
| `username=' OR '1'='1` | **403 — Cloudflare WAF** |
| `username=e3Dgin2r'AND'1'='1` | **403 — Cloudflare WAF** |
| `username=e3Dgin2r'\|\|'1` | **403 — Cloudflare WAF** |
| `birthdate=' OR 1=1` | **403 — Cloudflare WAF** |

Two compounding problems make this a dead end from outside:

1. Every payload with SQL-ish structure is blocked at the edge.
2. The three payloads that *did* reach the app returned a **byte-identical**
   response to the valid-credential baseline. Because the application emits the
   same generic error for valid and invalid credentials, there is **no
   observable channel** for error- or boolean-based detection.

A successful authentication bypass *would* have surfaced as a **302 to the SP**
instead of a 500, but no such payload ever reached the application.

**Conclusion: SQLi here can be neither confirmed nor excluded from outside.**
Only read-only probes were sent; no destructive payloads were used.

### Post-auth surface — unreachable

Blocked by the non-functional test accounts. Not covered: the study/DICOM
viewer, per-study object references, horizontal access between studies, the
`?code=` pre-fill path, and the `/dicom/` Shibboleth+eID flow. This is where the
RoE's real severities live (*access to a specific/random patient record*).

---

## Reportability (RoE filter)

| Item | RoE verdict |
| --- | --- |
| §1 cert hygiene (CA:TRUE, 9-yr, key reuse) | No PoC possible; crypto-hygiene only → not submittable |
| §2 SimpleSAMLphp 1.17.x / CVE-2019-3465 | *"Software out of date without a proof-of-concept"* excluded; EOL clause |
| §3 unsigned AuthnRequests accepted | No impact (ACS pinned, Issuer must resolve) → not a vuln |
| §4 `authenticate.php` exposed | Likely covered by *"verbose messages … without disclosing sensitive information"* |
| §5 shared docroot | Informational only |
| §6 WAF behaviour | Informational only |
| §7 `admin` auth source | Hardened correctly |
| All "found clean" items | Negative results, nothing to file |
| SQLi in `uzContact` | Unproven — would need a PoC to file |

No submission was made. Nothing found meets the bar.

---

## Artifacts

All under `recon/`.

**Responses / pages**

| File | Content |
| --- | --- |
| `idp-metadata.xml` | IdP SAML metadata (cert, endpoints, contacts) |
| `shib-sp-metadata.xml` | Shibboleth SP metadata + ACS/SLO bindings |
| `login-form.html`, `patient-final.html` | `uzContact` login page (GET + post-SSO) |
| `ds.html`, `uzcontact-index.html` | EDS page — byte-identical pair (§5) |
| `as-admin-chain.html` | Rendered `loginuserpass.php` (the `processing_trans` marker) |
| `trans-{en,nl,fr}.json` | Client i18n bundles (error strings, IdP cards) |

**Enumeration**

| File | Content |
| --- | --- |
| `dns.txt`, `whois.txt` | DNS records; Combell/Cloudflare registration |
| `http-headers.txt` | Full redirect chains for both hosts |
| `simplesaml-paths.txt`, `wellknown.txt` | SimpleSAMLphp endpoint + well-known sweeps |
| `uzContact-dir.txt`, `media-paths.txt`, `media-ds.txt` | Module dir and media-host sweeps |

**AuthnRequest signature probe (§3)**

| File | Content |
| --- | --- |
| `fresh-sso-url.txt` | Genuine signed AuthnRequest captured from the SP |
| `authnrequest-decoded.xml` | Decoded AuthnRequest XML |
| `var_{full,nosig,badsig,tampered}.txt` | The four probe URLs |
| `h_{full,nosig,badsig,tampered}.txt` | Response headers (all 302) |
| `b_{full,nosig,badsig,tampered}.html` | Response bodies |

**Version fingerprint (§2)** — `recon/fingerprint/`

| File | Content |
| --- | --- |
| `target_resources_*` | Downloaded `script.js`, `default.css`, icons (hashed) |
| `tpl17.php`, `tpl184.twig` | Upstream login templates showing the `processing_trans` delta |
| `AdminPassword.php`, `as_login.php` | Audited source |
| `cl-117.md` | 1.17 branch changelog |
| `staticfiles.txt` | Web-facing static file inventory |

The SimpleSAMLphp 1.17.6/1.17.7/1.17.8 source trees used for the audit are
**not** committed (50 MB, publicly available):
`https://codeload.github.com/simplesamlphp/simplesamlphp/tar.gz/refs/tags/v1.17.8`

### Reproduction highlights

```bash
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'

# 1. IdP metadata (cert, endpoints)
curl -s -A "$UA" https://idp-contact.nexuzhealth.be/simplesaml/saml2/idp/metadata.php

# 2. auth source disclosure
curl -s -A "$UA" https://idp-contact.nexuzhealth.be/simplesaml/module.php/core/authenticate.php

# 3. version fingerprint - hash the two static assets and match upstream tags
curl -s -A "$UA" https://idp-contact.nexuzhealth.be/simplesaml/resources/script.js | wc -c    # 789
curl -s -A "$UA" https://idp-contact.nexuzhealth.be/simplesaml/resources/default.css | wc -c # 7820

# 4. signature probe: capture a fresh signed AuthnRequest, then strip the signature
curl -s -A "$UA" -D - -o /dev/null https://media.nexuzhealth.be/patient/ | grep -i '^location:'

# 5. open-redirect whitelist check (expect 502 = rejected)
curl -s -A "$UA" -o /dev/null -w '%{http_code}\n' \
  "https://idp-contact.nexuzhealth.be/simplesaml/module.php/core/as_login.php?AuthId=uzContact&ReturnTo=https%3A%2F%2Fexample.com%2F"
```

---

## Housekeeping

⚠️ **Header discrepancy.** This RoE marks *User agent* and *Request header* as
"Not applicable", but the sibling `uzleuven` program from the **same
organisation** mandates `X-Intigriti-Username: eliam`. Confirm which applies to
`nexuzhealthwebpacs` before resuming — if a header is in fact required, the
requests recorded here would need re-running with it.

⚠️ **Do not touch** any host outside the two in-scope URLs, including the
~67 hostnames surfaced by the (dropped) subdomain enumeration.

⚠️ **Do not guess patient codes** — auto-lockout is documented in the RoE.

---

## Next

1. **Re-test the two test accounts.** Everything valuable is post-auth; if they
   work, start here. If they stay broken, ask the program owner — the accounts
   being dead is itself worth reporting as an engagement blocker.
2. If they work: map the study viewer, the `?code=` pre-fill, per-study object
   references, and horizontal access between studies. That is the *Exceptional /
   Critical* band.
3. Only if the IdP is touched again: check whether any `saml20-sp-remote` entry
   actually requires signed AuthnRequests or XML-signed messages — that is the
   one path that could revive CVE-2019-3465. Needs a PoC to be reportable.
4. Otherwise: **close the engagement.** No exploitable pre-auth issue found.

## Change log

- **2026-09-26** — Initial recon and enumeration. Fingerprinted SimpleSAMLphp
  1.17.x; audited all reachable pre-auth endpoints against upstream source;
  ran the AuthnRequest signature differential probe (all 4 variants accepted);
  attempted SQLi on the `uzContact` lookup (blocked by WAF / no signal);
  confirmed both test accounts non-functional. No submission made.
- **2026-09-26** — Scope discipline note added after dropping the out-of-scope
  subdomain enumeration.
```
(\_/)
(o.o)
(> <) rabbit-hole-research
```
