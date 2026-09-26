# Probe Summary — Axel Springer SE (Intigriti `axelspringerse`)

Date: 2026-09-26
Method: passive DNS + CT logs, non-intrusive HTTP GET of public roots.
RoE compliance: "Do not execute intrusive commands within production environments" honoured — no
fuzzing, no auth attempts, no exploitation. Only public root/page requests.

## 1. Scope extraction

- **39 apex/URL assets** → `targets.txt`
- **25 wildcard assets** → expanded via CT logs
- **12 in-scope IPs** → `ip-ranges.txt`
- Out of scope: `*.axelspringer.com`, `technik.*` handled, and everything unlisted

## 2. In-scope IP range — CONFIRMED DEAD

All 12 IPs (Tier 1) were re-checked with `nmap -Pn --top-ports 100` (`logs/nmap-iprange.txt`):

```
18.184.198.198  18.185.214.59  18.194.109.179  3.121.117.72  3.121.138.10
3.121.138.128   3.121.138.134  3.121.138.170   3.121.138.33  3.121.138.43
3.124.248.208   35.156.137.39
```

Result: **`All 100 scanned ports ... are in ignored states` — 99 filtered, 1 net-unreach, 0 open.**
This corroborates the prior finding that nothing is listening on TCP. The IP assets are
effectively unusable; spend effort on hostnames instead.

## 3. Apex host liveness (39 targets, `http-final.tsv`)

Live and serving content (HTTP 200 after redirect):

| Host | Final URL | Notes |
| --- | --- | --- |
| adtechnology.axelspringer.com | `/` | Apache/2.4.58 (Ubuntu), title "AS Adtechnology" — **Tier 1** |
| bild.de | https://www.bild.de/ | Akamai edge |
| m.bild.de | https://m.bild.de/ | Apache, Akamai `m.bild.de.edgekey.net` |
| welt.de | https://www.welt.de/ | Tier 1 |
| epaper.welt.de | `/` | nginx, CNAME `bkpublish-frontend.blaetterkatalog.de` |
| digital.welt.de | `/` | WELT Abo |
| signin.auth.welt.de | `/` | AmazonS3 fronting `consumer-next-web.prod.ps.welt.de` |
| go.welt.de | `/` | "WELTgo!" |
| meinkonto.bild.de | `/` | S3 fronting `userprofile-wrapper.prod.ps.bild.de` |
| hey.bild.de | `/` | "Hey" AI assistant |
| politico.eu | https://www.politico.eu/uk/?geo-redirect | Cloudflare |
| newsos.com | `/login?next=%2F` | **APISIX/3.17.0** gateway — Tier 2 |
| autobild.de / computerbild.de / fitbook.de / techbook.de / myhomebook.de / travelbook.de / petbook.de / wissen-sie-mehr.de | → www.* | mostly Akamai, several 403 WAF |
| spring-media.de | → https://career.axelspringer.com/de/ | redirect off-scope |
| bild.tv | → www.bild.de/tv/mediathek/... | redirect |
| sportbild.de | → sportbild.bild.de | redirect |

Blocked / WAF (403): emarketer.com (Cloudflare "Just a moment..."), bz-berlin.de,
ein-herz-fuer-kinder.de, fitbook.de, myhomebook.de, petbook.de, petbook-magazine.com,
techbook.de, travelbook.de, stylebook.de (→ fitbook.de).

401: bild.design → www.bild.design "Protected page".
503: dealer.prod.ps.axelspringer.de (awselb) — scope is `/purchases/*` only.

No DNS / no service:
- `asadcdn.com`, `auth.bild.de`, `springtools.de` — apex NXDOMAIN (wildcard-only; subdomains exist)
- `editorial.one` — resolves to RFC1918 `172.23.85.9/36/86` → internal only, unreachable
- `technik.autobild.de`, `technik.beta.autobild.de` — CNAME `www.autobild.de.dns.boreus.de` → 208.82.72.50, TCP timeout
- `germany.politico.eu` — CNAME `politico.tech.as-nmt.de` → NXDOMAIN

## 4. Subdomain enumeration (`crt-subdomains.txt`)

Passive CT (crt.sh) over the wildcard bases → **4,467 unique in-scope hostnames**, **428 resolve**,
**336 unique live hosts / 372 endpoints** (`live-endpoints.tsv`, `subdomains-http.tsv`).

Per-base counts: springtools.de 3717, bild.de 325, autobild.de 124, sportbild.de 72,
auth.bild.de 28, asadcdn.com 12, computerbild.de 11.

Status distribution: 200 ×237, 404 ×53, 403 ×53, 400 ×8, 401 ×7, 301 ×5, 402 ×3, 409 ×2,
1 each of 204/502/503/530.

### False positives — DO NOT TEST
36 `*.emarketer.com` names resolve to **8.8.8.8** and redirect to `https://dns.google/`
(`admin.emarketer.com`, `ads.emarketer.com`, `cas.emarketer.com`, `*-na1.emarketer.com`, …).
These are DNS sinkholes, not Axel Springer services.

### 4.1 Tier 1 high-value candidates

`*.auth.bild.de` (authentication / checkout — matches the "obtain sensitive user data" worst case):

| Host | Code | Notes |
| --- | --- | --- |
| login.bild.de | 200 | login surface |
| checkout.co.auth.bild.de | 200 | checkout |
| checkout-uat.co.auth.bild.de | 200 | **UAT checkout** |
| admin.checkout.co.auth.bild.de | 403 | admin checkout |
| admin.checkout-uat.co.auth.bild.de | 403 | admin checkout (UAT) |
| admin.checkout.prod.ps.bild.de | 502 | admin checkout (prod) |
| consumer-api.prod.auth.bild.de | 404 | consumer API |
| consumer-api.stage.auth.bild.de | 409 | staging API |
| consumer-api.uat.auth.bild.de | 404 | UAT API |
| int.kundenservice.auth.bild.de | 404 | internal kundenservice |
| kundenservice.auth.bild.de | 200 | subscription self-service |

Note: `aboservice.bild.de`, `aboservice.computerbild.de`, `aboservice.autobild.de` redirect to
`kundenservice.auth.axelspringer.de` — **that hostname is not listed in scope**, treat as
out-of-scope unless the program confirms otherwise.

`*.asadcdn.com` (ad serving, Tier 1):

| Host | Code |
| --- | --- |
| pbs.asadcdn.com | 200 |
| pbs-test.asadcdn.com | 200 |
| pbsb.asadcdn.com | 401 |
| staging.pbsb.asadcdn.com | 401 |
| test.pbsb.asadcdn.com | 401 |
| reports.asadcdn.com | 301 |
| status.asadcdn.com | 400 |
| tmi.asadcdn.com | 404 |

`*.bild.de` (Tier 2 wildcard) notable: `jobs.bild.de` 401, `internal2tree.bild.de` 404,
`aggregation.bild.de` 403, `asset.*` 403, `ory-poc-api.ps.bild.de` 409.

### 4.2 `*.springtools.de` (Tier 2) — internal tooling

| Host | Code |
| --- | --- |
| curato-test.ep.springtools.de | 200 |
| stream.springtools.de | 200 |
| stream-stage.springtools.de | 200 |
| categorization.springtools.de | 403 |
| categorization-stg.springtools.de | 403 |

3,717 CT names exist under this base (mostly generated preview hosts), only 5 serve HTTP.
`stream` / `stream-stage` and `curato-test` are the interesting internal-tool candidates.

### 4.3 Tier 2/3 other

- `managementapi.emarketer.com` 401 — **real** (AWS NLB `avp-iaas-service-public-nlb-1-*.elb.us-east-1.amazonaws.com`,
  34.235.51.164 / 3.234.118.51), unlike the `*-na1` sinkholes
- `staging.pbsb.asadcdn.com`, `test.pbsb.asadcdn.com` 401
- `dev.vibed.newsos.com` 503
- `productstorybundles.{autobild,fitbook,travelbook}.de` 404 (same app, multi-brand)

## 5. Suggested next steps

1. Manual browse `checkout*.co.auth.bild.de` + `consumer-api.*.auth.bild.de` (self-register an
   account, per FAQ) — closest match to the "sensitive user data" worst case.
2. Review `*.springtools.de` staging/stream services and `categorization*.springtools.de` 403s.
3. Test `*.asadcdn.com` test/staging (401) for auth bypass on ad-serving infra.
4. Crawl `newsos.com` (APISIX gateway) and `adtechnology.axelspringer.com` (Apache).
5. Ignore the 12 IPs and the 36 `emarketer.com` sinkholes.

## Files

| File | Contents |
| --- | --- |
| `scope.md` | Full extracted RoE (tiers, exclusions, bounties, worst cases) |
| `targets.txt` | 39 apex/URL assets |
| `ip-ranges.txt` | 12 in-scope IPs |
| `dns-resolved.tsv` | DNS A/CNAME for apex assets |
| `http-probe.tsv` / `http-final.tsv` | Apex HTTP probes (raw / redirect-followed) |
| `crt-subdomains.txt` | 4,467 CT subdomains |
| `resolved.tsv` | 428 resolving subdomains |
| `subdomains-http.tsv` | 372 probed endpoints (raw) |
| `live-endpoints.tsv` | 336 live endpoints, sinkholes excluded |
| `live-hosts.txt` | 336 unique live hostnames |
| `targets-priority.tsv` | 58 auth/admin/checkout/api/staging candidates |
| `logs/nmap-iprange.txt` | IP range port scan (0 open) |
| `probe-http.sh`, `probe-subdomains.sh`, `enum-crt.sh` | Reproducible probe scripts |
