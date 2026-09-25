#!/usr/bin/env python3
"""Automate the Port of Antwerp-Bruges *acceptance* registration wizard.

Reconstructed from the Burp export `register-accpt.portofantwerpbruges.com`.

Rules of engagement enforced in code, not by convention:
  * host is restricted to the acceptance registration hosts -- it is
    impossible to point this at the production `register.*` hosts;
  * the applicant e-mail must be an @intigriti.me address;
  * every request is throttled to 4 req/s (RoE cap is 5 req/s).

The captcha is NOT bypassed. `POST .../{id}/captchaimage` returns the challenge
JPEG, which is written to disk; a human reads it and types the characters back.
The client-generated captcha key (Math.random().toString(36).substr(2,10)) and
the typed value are then sent to `PUT .../{id}/captcha`, exactly as the SPA does.

Usage:
  ./poa_register.py --email eliam@intigriti.me --first eliam --last intigriti \
      --phone +3239999999 --company "Test Company BV" --address "Teststraat 1" \
      --city "2030 Antwerp" --app APICS --activities AGENT

  ./poa_register.py --list-apps --email eliam@intigriti.me   # browse the catalogue
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import random
import re
import ssl
import string
import sys
import time
import urllib.error
import urllib.request

ALLOWED_HOSTS = {
    "register-accpt.portofantwerpbruges.com",
    "register-test.portofantwerpbruges.com",
}
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")
MIN_INTERVAL = 0.25  # 4 req/s


class RoEViolation(RuntimeError):
    pass


class Client:
    def __init__(self, host: str, language: str = "EN",
                 sd_user: str = "none", insecure: bool = False):
        if host not in ALLOWED_HOSTS:
            raise RoEViolation(
                f"host {host!r} is not an in-scope acceptance registration host.\n"
                f"allowed: {', '.join(sorted(ALLOWED_HOSTS))}\n"
                "The production register.* hosts are out of scope."
            )
        self.base = f"https://{host}/account"
        self.origin = f"https://{host}"
        self.host = host
        self.language = language.upper()
        # The SPA sends this on every XHR. The first field is the framework's
        # notion of the current user ("none" while unauthenticated); the third is
        # the registration language. --sd-user lets us test whether the server
        # trusts a client-supplied identity here.
        self.sd_user = sd_user
        # Registration-scoped shared secret: issued by POST /registernewusers,
        # echoed back as X-Amaris-Registernewusersecret on every later call.
        self.secret: str | None = None
        self._last = 0.0
        self.count = 0
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        )

    def _throttle(self):
        dt = time.time() - self._last
        if dt < MIN_INTERVAL:
            time.sleep(MIN_INTERVAL - dt)
        self._last = time.time()
        self.count += 1

    def warmup(self):
        """Load the SPA shell first, as a browser does, to pick up the F5/CF
        cookies and to populate Referer/Origin naturally."""
        req = urllib.request.Request(f"{self.origin}/account/", headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.9",
        })
        self._throttle()
        try:
            with self.opener.open(req, timeout=30) as r:
                return r.status
        except Exception:
            return None

    def call(self, method: str, path: str, payload=None, raw=False):
        """Return (status, body). body is dict/list, str, or bytes when raw."""
        self._throttle()
        url = f"{self.base}{path}"
        data = None
        headers = {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-GB,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Origin": self.origin,
            "Referer": f"{self.origin}/account/",
            "X-Amaris-Securitydata": f"{self.sd_user},RAV,{self.language}",
        }
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        if self.secret:
            headers["X-Amaris-Registernewusersecret"] = self.secret
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=30) as r:
                body = r.read()
                status = r.status
        except urllib.error.HTTPError as e:
            body = e.read()
            status = e.code
        except Exception as e:  # network/TLS
            raise RuntimeError(f"{method} {path} failed: {e}") from e

        if raw:
            return status, body
        text = body.decode("utf-8", "replace").strip()
        try:
            return status, (json.loads(text) if text else None)
        except json.JSONDecodeError:
            return status, text


def require_intigriti_email(email: str) -> str:
    email = email.strip()
    if not re.fullmatch(r"[^@\s]+@intigriti\.me", email):
        got = email.rsplit("@", 1)[-1] if "@" in email else email
        raise RoEViolation(
            f"applicant e-mail must be an @intigriti.me address, got domain {got!r}.\n"
            "Registration without an @intigriti.me address is listed as an "
            "out-of-scope action in the program's rules of engagement."
        )
    return email


def new_captcha_key() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=10))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="register-accpt.portofantwerpbruges.com")
    ap.add_argument("--email", required=True)
    ap.add_argument("--first", default="eliam")
    ap.add_argument("--last", default="intigriti")
    ap.add_argument("--phone", default="+3239999999")
    ap.add_argument("--language", default="EN")
    ap.add_argument("--company", default="Test Company BV")
    ap.add_argument("--address", default="Teststraat 1")
    ap.add_argument("--city", default="2030 Antwerp")
    ap.add_argument("--country", default="BE")
    ap.add_argument("--vat-obligated", action="store_true")
    ap.add_argument("--app", help="application id, e.g. APICS")
    ap.add_argument("--activities", help="comma separated activity ids, e.g. AGENT,TPLOPERATOR")
    ap.add_argument("--codes", default="", help="comma separated application_codes, if the app needs them")
    ap.add_argument("--list-apps", action="store_true", help="create a draft and print the catalogue")
    ap.add_argument("--captcha-image", default="captcha.jpg")
    ap.add_argument("--captcha-value", help="skip the prompt (only valid for the current run)")
    ap.add_argument("--sd-user", default="none",
                    help="first field of X-Amaris-Securitydata (identity testing)")
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()

    try:
        email = require_intigriti_email(args.email)
        c = Client(args.host, args.language, args.sd_user, args.insecure)
    except RoEViolation as e:
        print(f"\n  REFUSING TO RUN\n  {e}\n", file=sys.stderr)
        return 2

    def step(label, method, path, payload=None, raw=False, expect=(200, 204)):
        status, body = c.call(method, path, payload, raw)
        ok = status in expect or (raw and status == 200)
        mark = "ok " if ok else "!! "
        shown = "" if raw else f" {str(body)[:90]}"
        print(f"  {mark}{method:5s} {status} {label}{shown}")
        if not ok:
            raise RuntimeError(f"{label} returned {status} (expected one of {expect})")
        return body

    print(f"\nRegistration against https://{c.host}/account  (as {email})\n")
    print(f"  ..  GET        warmup /account/ -> {c.warmup()}")

    reg = step("create draft", "POST", "/api/registernewusers", {})
    reg_id = reg["id"]
    c.secret = reg["secret"]
    print(f"  -> registration id {reg_id}  secret {c.secret}")

    # --- captcha: human in the loop, no control is bypassed -------------------
    key = new_captcha_key()
    status, img = c.call("POST", f"/api/registernewusers/{reg_id}/captchaimage", {"key": key}, raw=True)
    if status != 200:
        print(f"  !! captchaimage returned {status}", file=sys.stderr)
        return 3
    with open(args.captcha_image, "wb") as f:
        f.write(img)
    print(f"  ok  POST  200 captchaimage -> {len(img)} bytes written to {args.captcha_image}")

    if args.captcha_value:
        value = args.captcha_value.strip()
        print(f"  ok  using supplied captcha value {value!r}")
    else:
        print(f"\n  Open {args.captcha_image} and read the characters.")
        value = input("  captcha value: ").strip()
    if not value:
        print("  !! empty captcha value", file=sys.stderr)
        return 3
    step("submit captcha", "PUT", f"/api/registernewusers/{reg_id}/captcha",
         {"key": key, "value": value})

    step("registration language", "PUT", f"/api/registernewusers/{reg_id}/registrationlanguage",
         {"language": args.language})
    step("country list", "GET", f"/api/countries?language={args.language}")

    pol = step("policy guids", "GET", "/api/registernewusers/policy")

    step("personal details", "POST", f"/api/registernewusers/{reg_id}/personal", {
        "personal": {"first_name": args.first, "last_name": args.last, "email": email,
                     "telephone_number": args.phone, "language": args.language},
        "general_policy": {"policy_accepted": True, "policy_guid": pol["general_guid"]},
        "privacy_policy": {"policy_accepted": True, "policy_guid": pol["privacy_guid"]},
        "repeat_email": email,
    })

    apps = step("application catalogue", "GET", f"/api/registernewusers/{reg_id}/applications")

    if args.list_apps:
        _print_catalogue(apps)
        print(f"\n  draft {reg_id} left at personal-details stage (no application selected)\n")
        return 0

    if not args.app or not args.activities:
        print("\n  --app and --activities are required (or use --list-apps)\n", file=sys.stderr)
        _print_catalogue(apps)
        return 2

    chosen = next((e for e in apps if e["application"]["id"] == args.app), None)
    if chosen is None:
        print(f"\n  unknown application id {args.app!r}; see --list-apps\n", file=sys.stderr)
        return 2

    valid = {a["id"] for a in chosen["application"].get("activity_definitions", [])}
    wanted = [a.strip() for a in args.activities.split(",") if a.strip()]
    unknown = [a for a in wanted if valid and a not in valid]
    if unknown:
        print(f"\n  {args.app} does not define {unknown}; valid: {sorted(valid)}\n", file=sys.stderr)
        return 2

    step("company match", "GET", f"/api/registernewusers/{reg_id}/match")
    step("company details", "POST", f"/api/registernewusers/{reg_id}/company", {
        "name": args.company, "address": args.address, "city": args.city,
        "country": args.country, "telephone_number": args.phone, "email": email,
        "vat_obligated": args.vat_obligated,
    })

    app_pol = chosen["application"].get("privacy_policy_guid")
    step("select application", "PUT", f"/api/registernewusers/{reg_id}/application", {
        "id": args.app,
        "activities_and_codes": {
            "activities": wanted,
            "application_codes": [x.strip() for x in args.codes.split(",") if x.strip()],
        },
        "selected_communities": [],
        "policies": ([{"policy_accepted": True, "policy_guid": app_pol}] if app_pol else []),
    })

    final = step("final state", "GET", f"/api/registernewusers/{reg_id}")
    print(f"\n  registration {reg_id}")
    print(f"    submitted={final.get('submitted')}  i_am_a_robot={final.get('i_am_a_robot')}  "
          f"language={final.get('registration_language')}")
    print(f"    application={args.app}  activities={wanted}")
    print(f"  {c.count} requests total, throttled to 4 req/s")
    print("  Next: the confirmation e-mail. Check the @intigriti.me mailbox and follow the "
          "activation link.\n")
    return 0


def _print_catalogue(apps):
    print(f"\n  {len(apps)} applications available:")
    for e in apps:
        a = e["application"]
        cat = a.get("application_category") or "-"
        print(f"    {a['id']:16s} [{cat}]")
        for ad in a.get("activity_definitions", []):
            info = f"  <- {ad['information']}" if ad.get("information") else ""
            print(f"        {ad['id']:20s} {ad.get('description','')}{info}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, RoEViolation) as exc:
        print(f"\n  FAILED: {exc}\n", file=sys.stderr)
        sys.exit(1)
