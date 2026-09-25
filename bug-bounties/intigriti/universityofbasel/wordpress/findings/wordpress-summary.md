# WordPress audit — three DBE/DMI sites (Intigriti UniBas VDP)

All three are IN SCOPE (`*.unibas.ch` + `131.152.0.0/16`).
Tooling: wpscan 4.0.1 with API token, RoE `User-Agent` + `X-Intigriti-Username`,
`--throttle 250` (<=4 req/s, cap is 5), `--disable-tls-checks` where needed.
No brute-force / password options were used (out of scope).

| Host | IP | WordPress | Theme | Notable plugins | TLS |
|---|---|---|---|---|---|
| dbe-events.dbe.unibas.ch | 131.152.226.103 | 7.1.2 | escapade 1.1.3 (current) | the-events-calendar 6.16.3, registrations-for-the-events-calendar 3.1, enable-media-replace 4.1.9 | valid |
| dmi-sphexa.dmi.unibas.ch | 131.152.238.60 | 7.1.2 | inspiro 1.8.7 (**outdated**) | akismet 2.5.0-3.1.4 | **INCOMPLETE CHAIN** |
| ispdc2022.dmi.unibas.ch | 131.152.217.207 | 6.4.12 | nisarg 1.5 (**outdated**) | **woocommerce 8.5.5**, akismet (old), collapse-o-matic 1.8.5.5 | valid |

(`dmi-ispdc2022.dmi.unibas.ch` 301-redirects to `ispdc2022.dmi.unibas.ch`.)

## Vulnerability findings and why none is reportable

### dbe-events — The Events Calendar 6.16.3 (8 known vulns)
Patch dates vs the program's "zero-day reported within **14 days** of patch release"
exclusion (today 2026-09-24, cut-off 2026-09-10):

| CVE | Issue | Fixed | Released | Window |
|---|---|---|---|---|
| CVE-2026-78159 | Unauthenticated RCE (widget `classes` map) | 6.17.3.1 | 2026-08-26 | outside (29d) |
| CVE-2026-78265 | Unauthenticated PHP Object Injection | 6.17.3 | 2026-08-20 | outside (35d) |
| CVE-2026-13390 | Unauth Event Aggregator import-status manipulation | 6.16.5.1 | 2026-07-01 | outside (85d) |
| CVE-2026-78006 | Unauthenticated POI (is_safe_widget_instance bypass) | 6.17.4.1 | 2026-09-10 | borderline |
| CVE-2026-84741/2/3/5 | Unauth venue/organizer disclosure; Contributor+ publication/takeover | 6.17.5 | 2026-09-17 | **excluded (7d)** |

Blockers, all verified:
- **RCE not reachable.** The advisory requires "comments enabled on `tribe_events` posts
  and at least one comment containing a crafted `wp:legacy-widget` block". Observed:
  single-event page renders **no comment form**; `comment_status = null`;
  `GET /wp-json/wp/v2/comments?post=639` -> **0 comments**. The `do_blocks()` path is
  never reached, so no exploit is possible (and none was attempted).
- **POI unprovable**: advisory states "No known POP chain is present in the vulnerable
  software" — needs a gadget chain from another component.
- **Import-status manipulation is state-changing** (would mutate production data).
- Contributor+/Editor+ issues (`registrations-for-the-events-calendar` SQLi,
  `enable-media-replace` XSS) need a role; `/wp-login.php?action=register` -> 302 =
  registration disabled.
- Disclosure CVEs fall inside the 14-day exclusion.
- `GET /events` reported 0 events, but WP core REST shows **1** event ("Test Event 2026")
  -> the site is effectively a **test instance**.

### dmi-sphexa
- `akismet` 2.5.0-3.1.4 -> "Unauthenticated Stored XSS". Not reachable: **no comment
  form** on the site; stored XSS in Akismet only fires for an admin viewing a comment.
- `inspiro` < 2.1.3 -> CSRF to arbitrary plugin installation (needs an admin victim).
- **Incomplete TLS certificate chain** (`verify error: unable to get local issuer
  certificate`, `Verify return code: 21`). Let's Encrypt cert for
  `dmi-sphexa.dmi.unibas.ch` served without its intermediate. Real misconfiguration,
  but cert/TLS issues are not in the program's reportable classes and the realistic
  impact (MITM) is explicitly excluded.

### ispdc2022 — WooCommerce 8.5.5 (latest 11.1.2, ~2.5 years behind)
Unauthenticated entries in the advisory list, and why each is not reportable:
- `< 9.1.0` Unauthenticated **HTML Injection** -> program's known-issue list
  ("Reflected XSS / HTML Injection affecting existing input parameters").
- `< 9.4.3` Unauthenticated **Order Creation** -> write action; the store is **empty**
  (`/wp-json/wp/v2/product` -> `[]`, `/shop/` -> 404), so there is no meaningful impact.
- `< 11.1.0` Unauthenticated **DoS** -> excluded ("DoS/DDoS attacks"), and testing it
  is exactly what must not be done.
- `< 9.4.3` **Reflected XSS** -> known-issue/excluded class.
- Everything high-value (Shop Manager+ **SQLi** x2, several stored XSS, PII leak,
  Contributor+ private/draft product access) requires an authenticated role.
  Registration is disabled here too -> no account obtainable.
- Also present: `collapse-o-matic` 1.8.5.5 (Contributor+ stored XSS), `nisarg` 1.5.

## Excluded-class observations (deliberately not reported)
- XML-RPC enabled on all three -> explicitly excluded ("XMLRPC enabled")
- `readme.html` + plugin/theme version disclosure -> excluded ("Banner grabbing/Version disclosure")
- External `wp-cron.php` reachable -> low, standard
- Organizer email `gabriela.oser@unibas.ch` in the TEC REST organizer listing -> a
  public-role staff contact, not sensitive PII

## Verdict
**No reportable vulnerability identified across the three WordPress sites.**
The real story is *maintenance*: WooCommerce 8.5.5 (~2.5 years old), Akismet ~2.5.0-3.1.4,
The Events Calendar 6.16.3, and two outdated themes — with a substantial CVE list — on
sites where the unauthenticated vectors are precondition-blocked, excluded by class,
state-changing on empty data, or inside the 14-day zero-day window, and where the
authenticated vectors are unreachable because registration is disabled.

Reporting the version gap alone would be rejected under "software out of date/vulnerable
without a proof-of-concept" and "reports that state that software is out of date without
a PoC". This is worth raising with the university as a maintenance issue outside the VDP,
not as a vulnerability submission.
