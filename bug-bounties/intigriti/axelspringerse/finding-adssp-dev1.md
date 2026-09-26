# Draft Finding — Internet-exposed, unpatched ManageEngine ADSelfService Plus

**Program:** Intigriti / Axel Springer SE (AS National Media & Tech)
**Asset:** `dev1.epaper.welt.de` … `dev5.epaper.welt.de` (Tier 2 — matches `*.welt.de`)
**Date:** 2026-09-26
**Product:** ManageEngine ADSelfService Plus, **build 6519**
**Status:** version-confirmed, **not exploited**

---

## Summary

Five internet-facing hosts under `*.welt.de` serve a **ManageEngine ADSelfService Plus** instance
(branded "004 GmbH – Account Self Service") running **build 6519**, which is vulnerable to **four
known HIGH-severity CVEs** per the vendor's own advisory page. ADSelfService Plus is a privileged
identity-management product — the application that brokers password resets, account unlocks and MFA
enrolment for the user population — and this instance is reachable from the public internet.

## Affected hosts

All five resolve to the same backend (`asse-dev.004dev.com`, `217.89.46.122`, nginx/1.31.3) and
return HTTP 200 with an identical build marker:

```
dev1.epaper.welt.de   200   build=6519
dev2.epaper.welt.de   200   build=6519
dev3.epaper.welt.de   200   build=6519
dev4.epaper.welt.de   200   build=6519
dev5.epaper.welt.de   200   build=6519
```

## Evidence

**Build identification.** Every static asset on the login page carries the build in its query
string, consistent across all five hosts and stable across repeated fetches:

```
/js/AjaxAPI.js?build=6519
/js/CommonUtil.js?build=6519
/js/Esearch.js?build=6519
/js/CustomLogonScript.js?build=6519
/js/form-util.js?build=6519
```

**Product confirmation.** `JSESSIONIDADSSP` session cookie, Zoho `zsec` URL-validator library, and
`adssp_*` locale keys (`adssp_login_user_page_domain_user_t…`, `adssp_security_…`). Error responses
return the product namespace directly:

```json
{"eSTATUS":"adssp.security.exception.pattern_not_matched"}
```

**Vulnerable CVEs** (from `manageengine.com/products/self-service-password/advisory/` — build 6519
falls inside every affected range below):

| CVE | Severity | Affected | Fixed in | Nature |
| --- | --- | --- | --- | --- |
| CVE-2026-3183 | **High** | 6523 and earlier | 6524 | **Broken authentication** — incomplete session-level auth state checks at a sensitive API endpoint let an attacker **with a valid user password bypass MFA** and gain unauthorised account access |
| CVE-2026-1367 | **High** | 6522 and earlier | 6523 | **SQL injection** (authenticated technician) |
| CVE-2026-2740 | **High** | 6524 and earlier | 6525 | **Authenticated RCE** in the remote agent installation workflow |
| CVE-2026-11374 | High | 6528 and earlier | 6529 | Vulnerability when deployed as an integrated AD360 component |

Note the build is only *one* release behind several fixes — it sits exactly on the boundary:
**CVE-2025-11250** (Critical) was "builds 6518 and earlier, fixed in 6519", so this deployment was
patched for the critical one but has since fallen four advisories behind.

## What I did and did not do

**Did:** unauthenticated version fingerprinting, public-endpoint enumeration, and read-only
inspection of client-side code.

**Did not:** exploit any CVE, attempt authentication, attempt MFA bypass, submit passwords, or run
any write operation. No account was created and no data was retrieved from the application.

## Impact

- An identity-management system reachable from the internet is high-value infrastructure: it
  brokers credentials and MFA for the wider user base.
- **CVE-2026-3183 is the material one** — MFA bypass with just a valid password defeats the
  strongest control a password-reset portal offers.
- This is a **dev-instance** hostname, which suggests it should not be internet-facing at all.

## Caveats (stated deliberately)

1. **No PoC.** These are version-based deductions from the vendor advisory; I did not confirm
   exploitability. The RoE states *"Submissions without proof of concept will not be considered"* —
   so this may be triaged as informational unless the programme accepts patch-lag findings.
2. **All four CVEs require some access** — a valid user password, or technician authentication.
   None is an unauthenticated RCE, so this is *"vulnerable software exposed"*, not *"trivially
   exploitable"*.
3. **CVE-2026-11374** only applies if the deployment is integrated into ManageEngine AD360;
   unverified here.
4. **Third-party hosting.** The application is a vendor product (004 GmbH) hosted on a `*.welt.de`
   name. In scope by the wildcard, but remediation sits with the vendor.

## Recommended remediation

1. Patch ADSelfService Plus to **build 6529 or later** (covers all four).
2. Remove internet exposure from `dev1–5` — dev instances of an IdP should sit behind VPN/allowlist.
3. If public exposure is required, MFA-bypass and RCE-class advisories should drive an emergency
   patch SLA rather than routine cadence.

## Secondary observation (not a finding)

`POST /UnAuthAction.cc` with `methodToCall=populateEmpSearch` is reachable **unauthenticated**
(HTTP 200) and drives the employee-search widget on the login page. The `methodToCall` parameter is
a **Struts2 Dynamic Method Invocation** primitive — normally able to invoke arbitrary action
methods — but the deployment enforces a **method-name allowlist**, which correctly rejects
dangerous values:

```
methodToCall=show              -> 400 {"eSTATUS":"adssp.security.exception.pattern_not_matched"}
methodToCall=serverSettings    -> 400 {"eSTATUS":"adssp.security.exception.pattern_not_matched"}
methodToCall=populateEmpSearch -> 200 (allowed)
```

Case variation, trailing whitespace, and null-byte padding were all rejected identically — the
control holds. `populateEmpSearch` returns an empty body on this instance (the employee-search
feature is disabled, so the page never renders the `Esearch` container).

**One thing I deliberately stopped short of:** requests using Struts2 bang-DMI path syntax
(`UnAuthAction!serverSettings.cc`, `UnAuthAction.cc!serverSettings`) **wedged the connection twice**,
surviving both `curl -m 12` and `timeout 15`. Because repeatedly triggering that on a live system
risks availability impact, I ceased testing it rather than pursuing it. The host remained healthy
afterwards (HTTP 200 in 0.21 s), so no damage was observed. **Worth a careful, rate-limited
follow-up** — an input that reliably stalls the worker is potentially a DoS, but confirming it is a
destructive test that needs explicit authorisation and a controlled approach.
