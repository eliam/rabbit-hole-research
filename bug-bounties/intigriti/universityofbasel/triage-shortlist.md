# CIDR sweep triage — 280 in-scope hosts (ports 22,53,80,443,8080,8443)

Source: `nmap_targets_scanned.txt` (+ masscan_open.txt, nmap_targets.txt), parsed to `parsed_hosts.json`.
281 hosts parsed, 280 in-scope. Ports seen: 443 (256), 80 (254), 22 (10), 8080 (10), 8443 (4), 53 (1).

## SCOPE NOTES (act on these before testing)
- **`131.152.225.8` → EXCLUDED.** It sits inside the program's excluded `131.152.225.0/26`.
  Do not test (it appeared as `ucmobile.swisstph.ch`, port 8443).
- **`131.152.222.150:8443`** presents cert `CN=workspace.ukbb.ch` and returns
  "Missing route token in request" — a different institution (UKBB, children's hospital),
  not `*.unibas.ch`. Treated as out of scope; not probed further.
- PTR names are not authoritative for in-scope hostnames (a service can be published under a
  `*.unibas.ch` vhost even when the PTR differs), so the IP range was used as the working
  criterion, per researcher direction. The IP-range asset is listed in the program.

## ALREADY CHECKED AND CLEARED (no finding)
| Target | Check | Result |
|---|---|---|
| lzm-svl-elastic01/02 (`.217.234/235`) | Elasticsearch unauth | **401 `security_exception`** — security enabled |
| lzm-kibana (`.238.57`) | Kibana unauth | only `/api/status` + `/login` public; all data APIs 401, apps 302->login |
| ns2-ext (`131.152.227.93`) | DNS AXFR | refused (0 records) |
| its-jenkins (`.238.33`) | Jenkins | 443 never completes a TLS handshake for us; http 301s to itself. Effectively unreachable |
| REDCap x3 | version | `redcap.scicore` + `redcap-stcs-ubuntu` = **17.3.13**; `fp-dmz-redcap` = **16.0.33**. REDCap CVEs in NVD are 2012-13 era (long fixed); version disclosure is an excluded class |
| nmc-hp5-24:8080 | WordPress + H5P | WordPress with **H5P 1.17.9 = current release** (2026-07-30) + akismet (old, needs a comment form) |
| fp-dmz-meet | Jitsi | `anonymousdomain: guest.meet.psychologie.unibas.ch` — anonymous guest access by design; `config.js` public, no secrets |
| lzm-medme-be/fe/pub:8080 | Spring Boot actuator | root/`/env`/`/mappings` **401 (good)**; `/actuator/health` is unauth and leaks DB type (PostgreSQL) -> excluded "verbose info" class |
| psycherocks (`131.152.191.66`) | Go server | all probed paths 404 |
| its-expressway-e1/e2 | Cisco | 8443 returns `400 Bad Request`; not reachable as-is |

## RANKED SHORTLIST — worth pursuing

### Tier 1
1. **IAM / OAuth surfaces** — `its-iam-viaweb-prod-001`, `its-iam-dist-ext`, `its-web-oauth-logon-001`
   (`.215.116`, `.217.177`, `.215.44`). Auth logic bugs are high impact and are **not** in the
   excluded list. Test redirect_uri validation, token/refresh handling, SAML/OIDC flows, logout
   invalidation (note: "sessions not invalidated" IS excluded — focus on authorisation bypass).
2. **Relution MDM** — `fp-dmz-mdm.psycho.unibas.ch` (`.191.76`). MDM portals are high-value;
   check version, enrolment/API endpoints, and auth. Version not disclosed on the landing page.
3. **k8s / envoy + nginx ingresses** — `ingress-k001..k007`, `ingress-005`, `ingress-002`, `ingress-003`
   (`.214.20`, `.21`, `.22`, `.24`, `.26`, `.10`, `.3`) plus the ~40 `*-backend.scicore.unibas.ch`
   hosts. These front many apps: run **vhost discovery** (`Host:` fuzzing, as done for Traefik) —
   unlisted vhosts are where exposed apps hide.
4. **Cisco Expressway** `its-expressway-e1/e2` (`.227.68/69`) — Expressway has a CVE history;
   needs correct SNI/Host to reach the admin UI. Verify version before considering anything.

### Tier 2
5. **`fp-dmz-support` (`.191.111`)** — a **second Zammad** instance ("Fakultät für Psychologie
   Helpdesk"). We found the other Zammad hardened, but re-verify this one (different config).
6. **`transcriptiones.dg.unibas.ch:8080`** (`.217.178`) — **Apache httpd 2.4.41** (2020, EOL).
   Returns 302. Worth a look at the app behind the redirect.
7. **`dhlab-journey-star.dhlab.unibas.ch:8080`** (`.238.52`) — "Visualizations" app returning 200;
   check for unauthenticated data access.
8. **`zuv-lernboerse.zuv.unibas.ch`**, **`dbe-derm-labeling`**, `dbe-derm` — 302s to app behind.
9. **`dasch-test-01..31`** (30 hosts, `.217.x`, `.238.x`) — long-lived test VMs; look for default
   pages, leftover installs, error pages. Avoid brute-forcing creds (excluded).

### Tier 3 / lower
10. `nmc-hp5-24` WordPress (H5P current; akismet old), `nmc-monitor-24`, `its-cs-sched01` (Jetty 403),
    `vpn.unibas.ch` / `webvpn.unibas.ch` (well-maintained, but worth a version check).

## BIGGEST GAP: port coverage
The sweep only covered **22,53,80,443,8080,8443**. That misses exactly the ports that produce
high-severity findings: **9200/9300** (Elasticsearch), **5601** (Kibana), **3000** (Grafana),
**2375/2376** (Docker API), **6443/10250** (Kubernetes), **6379** (Redis), **27017** (Mongo),
**5432/3306** (DB), **9000** (MinIO/PHP-FPM), **8081-8086**, **9200**, **11211**, **8080 alt**,
**15672** (RabbitMQ), **9090** (Prometheus), **9200**, **2379** (etcd).
Recommend a wide TCP sweep across the 280 live hosts (or at least the Tier-1 subset) before
concluding the surface is mapped.
