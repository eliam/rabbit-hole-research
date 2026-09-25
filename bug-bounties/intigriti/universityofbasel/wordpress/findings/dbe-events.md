# WordPress audit — dbe-events.dbe.unibas.ch

Asset      : 131.152.226.103 — IN SCOPE
Host       : dbe-events.dbe.unibas.ch   (no alias; cert valid)
Stack      : Apache/2.4.58 (Ubuntu), WordPress 7.1.2, theme `escapade` 1.1.3 (current)
Character  : appears to be a **test/staging instance** — exactly one event, titled "Test Event 2026"
Date       : 2026-09-24
Tooling    : wpscan 4.0.1 with API token, RoE UA + `X-Intigriti-Username`,
             `--throttle 250` (<=4 req/s), no password/brute-force options

## Plugins found (wpscan, aggressive detection)

| Plugin | Installed | Latest | Notes |
|---|---|---|---|
| the-events-calendar | **6.16.3** | 6.17.5 | 8 vulnerabilities (below) |
| registrations-for-the-events-calendar | 3.1 | 3.2.2 | Contributor+ SQLi (`standard` param), CVE-2026-13119 |
| enable-media-replace | 4.1.9 | 4.2.2 | Editor+ stored XSS, CVE-2026-57722 |

## The Events Calendar 6.16.3 — vulnerability analysis

Patch release dates (from the plugin's trunk changelog) vs the program's rule
"zero-day vulnerabilities reported within **14 days** of the public release of a
patch are excluded". Today = 2026-09-24, so the cut-off is 2026-09-10.

| CVE | Issue | Fixed in | Released | In 14-day window? |
|---|---|---|---|---|
| CVE-2026-78159 | **Unauthenticated RCE** via widget `classes` map | 6.17.3.1 | 2026-08-26 | no (29d) |
| CVE-2026-78265 | Unauthenticated PHP Object Injection | 6.17.3 | 2026-08-20 | no (35d) |
| CVE-2026-13390 | Unauthenticated Event Aggregator import-status manipulation | 6.16.5.1 | 2026-07-01 | no (85d) |
| CVE-2026-78006 | Unauthenticated POI (is_safe_widget_instance bypass) | 6.17.4.1 | 2026-09-10 | borderline (14d) |
| CVE-2026-84741/2/3/5 | Unauth venue/organizer disclosure; Contributor+ publication & takeover | 6.17.5 | 2026-09-17 | **excluded** (7d) |

6.16.3 predates every fix, so all of the above *version-match* the instance.

### Why nothing was confirmed exploitable
1. **CVE-2026-78159 (the RCE) is not reachable on this instance.** The advisory states
   the chain "requires that the targeted site has comments enabled on `tribe_events`
   posts **and** that at least one comment containing a crafted `wp:legacy-widget`
   block has been submitted". Verified preconditions:
   - the single-event page renders **no comment form**
   - `tribe_events` REST metadata: `comment_status = null`
   - `GET /wp-json/wp/v2/comments?post=639` -> **0 comments**
   So comments are closed on events: the required comment cannot be authored and the
   `do_blocks()` path is never reached. No exploit attempt was made (none is possible).
2. **CVE-2026-78265 (POI)** — advisory: "No known POP chain is present in the vulnerable
   software. If a POP chain is present via an additional plugin or theme ... it could
   allow ... execute code." Without a POP chain this is not demonstrable, and proving it
   would require sending serialized payloads at a production host.
3. **CVE-2026-13390** is a *state-changing* action (import-status manipulation); testing
   it would mutate production data, and impact on a test instance is unclear.
4. The Contributor+/Editor+ issues (TEC publication/takeover, `registrations-for-the-events-calendar`
   SQLi, `enable-media-replace` XSS) all need an authenticated role.
   `GET /wp-login.php?action=register` -> **302** = registration disabled, so no account
   could be obtained.

## Excluded-class observations (not reportable under this program)
- XML-RPC enabled (`xmlrpc.php` responds) -> explicitly excluded ("XMLRPC enabled")
- `readme.html` and plugin versions disclosed -> excluded ("Banner grabbing/Version disclosure")
- External WP-Cron reachable (`wp-cron.php`) -> low, standard
- Organizer email `gabriela.oser@unibas.ch` exposed via the TEC REST organizer listing ->
  a staff contact for a public-facing role, not sensitive PII

## Verdict
**No reportable finding.** The instance runs a demonstrably outdated, vulnerable plugin
version, but every unauthenticated vector is either precondition-blocked (RCE: comments
closed), unprovable without a POP chain (POI), state-changing (import manipulation), or
inside the program's 14-day zero-day exclusion (the 6.17.5 fixes). Reporting the version
gap alone would be rejected under "software out of date/vulnerable without a
proof-of-concept". Recorded so the analysis is not repeated.
