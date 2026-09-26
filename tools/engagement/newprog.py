#!/usr/bin/env python3
"""
newprog — scaffold a new bug-bounty / VDP engagement folder.

Codifies the standard engagement kickoff:

    1. create the folder for the vendor under the platform
    2. grab the RoE with `links -dump`
    3. drop an AGENTS.md so Copilot picks up the engagement rules when you
       scope a session to the folder (AGENTS.md is read from the cwd)
    4. print the kickoff prompt that tells Copilot to read the RoE and start
       enumerating the reported targets

Folder layout created:

    <base>/<platform>/<slug>/
        <slug>.RoE                Rules of engagement, dumped verbatim
        AGENTS.md                 standing rules for this engagement (Copilot)
        README.md                 deliverable, house structure + sig appended
        recon/                    raw evidence (responses, dumps, probes)
        runs/                     timestamped scan runs (masprobe output)

RoE facts (rate limit, user agent, required header, exclusions, scope assets)
are extracted best-effort from the dump and written into both AGENTS.md and
the README. They are ALWAYS marked for manual verification — the RoE text is
the source of truth, and a misread rate limit or header is a real problem.

Usage:
    newprog -p intigriti -n nexuzhealthwebpacs --roe-url https://app.intigriti.com/...
    newprog -p intigriti -n universityofbasel --kind vdp --roe-url https://...
    newprog -p intigriti -n acme --roe-file /tmp/acme-dump.txt
    newprog -p intigriti -n acme --roe-url https://... --dry-run

The RoE is fetched with `links -dump`. Program pages behind a login will dump
the login wall instead, so pass --roe-file with a dump you made from an
authenticated browser session. ALWAYS eyeball the resulting .RoE.
"""

import argparse
import re
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

SCRIPT = Path(__file__).resolve()
REPO_ROOT = SCRIPT.parents[2]          # tools/engagement/newprog.py -> repo root
SIG_FILE = REPO_ROOT / "sig.txt"

PLATFORMS = ("intigriti", "hackerone", "bugcrowd", "yeswehack", "other")
KINDS = ("bounty", "vdp")

# --------------------------------------------------------------------------- #
# RoE extraction
# --------------------------------------------------------------------------- #

# In an Intigriti dump the rules-of-engagement panel renders as a label line
# followed by its value, e.g.
#     User agent
#     Intigriti-UniBas-VDP-{username} Mozilla/5.0 (compatible; BugBountyResearcher)
_ROE_FIELDS = {
    "user_agent": "User agent",
    "rate_limit": "Automated tooling",
    "request_header": "Request header",
}

_CIDR_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")
# A bare hostname, optionally wildcarded, optionally with :port and/or /path.
_HOST_RE = re.compile(
    r"^\*{0,2}\.?[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*"
    r"\.[a-z]{2,}(?::\d{1,5})?(?:/[^\s]*)?$",
    re.I,
)
# Reject prose that merely ends in a dotted token.
_HOST_DENY = re.compile(
    r"^(https?|ftp)://|\.(js|css|png|jpe?g|gif|svg|ico|pdf|zip|gz|txt|html?)$", re.I
)


def _clean(value: str) -> str:
    """Normalise a captured RoE value; '' means 'not applicable'."""
    v = (value or "").strip().strip(".")
    if not v or v.lower() in {"not applicable", "n/a", "none", "-"}:
        return ""
    return v


_KNOWN_LABELS = {v.lower() for v in _ROE_FIELDS.values()}


def _looks_like_continuation(line: str) -> bool:
    """True if `line` plausibly continues the previous value rather than
    starting a new section, list, or paragraph."""
    s = line.strip()
    if not s:
        return False
    if s.lower() in _KNOWN_LABELS:
        return False
    if s.endswith(":"):
        return False
    if s[0] in "*-•#|":
        return False
    if len(s.split()) > 8:
        return False
    return True


def _value_after(lines: list, label: str) -> str:
    """Return the value following a `label` line, re-joining wrapped lines.

    `links -dump` breaks long values at word boundaries, and the break point
    depends on the terminal width, so line length cannot be used to detect a
    wrap. We instead consume following lines until one no longer looks like a
    continuation (a known label, a blank line, a list item, or prose).
    """
    for i, ln in enumerate(lines):
        if ln.strip().lower() != label.lower():
            continue
        j = i + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        if j >= len(lines):
            return ""
        parts = [lines[j].strip()]
        while len(parts) < 4 and j + 1 < len(lines):
            if not _looks_like_continuation(lines[j + 1]):
                break
            j += 1
            parts.append(lines[j].strip())
        return " ".join(parts)
    return ""


def parse_roe(text: str) -> dict:
    """Best-effort extraction of the facts we must not get wrong."""
    lines = text.splitlines()
    facts: dict = {k: "" for k in _ROE_FIELDS}

    for key, label in _ROE_FIELDS.items():
        facts[key] = _clean(_value_after(lines, label))

    cidrs = []
    for c in _CIDR_RE.findall(text):
        if c not in cidrs:
            cidrs.append(c)
    facts["cidrs"] = cidrs

    hosts = []
    seen = set()
    for raw in lines:
        ln = raw.strip()
        if _HOST_DENY.search(ln):
            continue
        if _HOST_RE.match(ln):
            h = ln.lower().rstrip(".,;")
            if h not in seen:
                seen.add(h)
                hosts.append(h)
    facts["hosts"] = hosts

    return facts


def _bullet(value: str, fallback: str) -> str:
    return value if value else fallback


# --------------------------------------------------------------------------- #
# Templates
# --------------------------------------------------------------------------- #

AGENTS_TEMPLATE = """\
# AGENTS.md — {name} engagement ({platform}, {kind})

Standing instructions for any Copilot session scoped to this folder.

## Read this first

The single source of scope truth is **`{name}.RoE`** in this directory. Read it
in full before touching anything, and re-read the scope and out-of-scope
sections before making any claim about a finding. If anything below disagrees
with the RoE, **the RoE wins**.

## Rules of engagement (extracted from the RoE — VERIFY BEFORE TESTING)

- **Rate limit**: {rate_limit}
- **User agent**: {user_agent}
- **Required request header**: {request_header}
- No DoS/DDoS, no brute force, no credential stuffing.
- No spam, social engineering, or physical intrusion.
- Safe harbour applies.
{exclusions_block}
> Verify every line above against `{name}.RoE` yourself. A misread rate limit or
> a missed required header invalidates the engagement.

## Scope discipline (hard rule)

- Test **only** assets the RoE explicitly lists. If it is not listed, it is out
  of scope — the RoE almost always says so in as many words.
- **Do not enumerate subdomains** unless the RoE scope is wildcard-based (e.g.
  an explicit `*.example.com` asset). For a fixed list of hosts, subdomain
  enumeration is scope creep and produces nothing but out-of-scope targets.
- **RoE check**: {wildcard_note}
- Never follow redirects off an in-scope host without stopping to check whether
  the destination is in scope.
- If a scan is owed to another machine, never assume it is finished — ask.

## Evidence layout

| Path | Contents |
| --- | --- |
| `recon/` | raw responses, dumps, probe output, decoded artefacts |
| `runs/<timestamp>/` | scanner output (masprobe etc.) — see `tools/enum/masprobe.py` |
| `README.md` | the deliverable; findings live here |
| `{name}.RoE` | never edit — it is the scope record |

Write raw evidence to disk as you go, and reference the filename from the README
so every claim is reproducible.

## README requirements

Follow the house structure used by the sibling engagements:

1. Rules of engagement (observed)
2. Scope (table) + scope-trap note
3. Environment / architecture
4. Findings — numbered, each labelled *finding* / *hardening* / *informational*
5. Tested and found clean (the bulk — document negatives with rigour)
6. Not testable / blocked
7. Reportability (RoE filter) — map each item to the clause that gates it
8. Artifacts + reproduction highlights
9. Housekeeping, Next, Change log

The README must end with the signature block from `sig.txt`, fenced:

````
```
(\\_/)
(o.o)
(> <) rabbit-hole-research
```
````

## Methodology

- **Fingerprint before probing.** Version strings, asset hashes, and framework
  markers beat guessing. For open-source components, diff upstream releases to
  find the exact security-relevant delta, then reason about reachability.
- **Prove negatives the same way you prove positives.** Record *how* a control
  was ruled out, not just that it was.
- **Apply the RoE's out-of-scope list before you call something a finding.**
  "Out of date without a PoC", "verbose errors without sensitive data", and
  "missing security headers" are the usual disqualifiers.
- **Distinguish a finding from a lead.** If it needs a PoC you do not have, say
  so plainly.
- Prefer read-only probes. Never run destructive payloads to confirm a hunch.
"""

README_TEMPLATE = """\
# {name} — {platform} {kind} engagement notes

Running notes for the **{name}** program on {platform}.
Reference: `{name}.RoE`. All testing stayed within the published RoE.

> **Status:** enumeration in progress.
> **Outcome:** TBD — no submission made yet.

---

## Rules of engagement (observed)

- **Rate limit**: {rate_limit}
- **User agent**: {user_agent}
- **Required request header**: {request_header}
- No DoS/DDoS, no brute force. Safe harbour applies.

> Extracted from the RoE automatically — **verify against `{name}.RoE`.**

---

## Scope

Asset list from `{name}.RoE`:

{scope_block}

**Everything not listed is out of scope.** The RoE states this explicitly in
almost every case; quote it in the README once confirmed.

### Scope discipline note

{wildcard_note}

---

## Environment / architecture

<!-- per-host roles, product fingerprints, shared infrastructure -->

---

## Findings

<!-- Numbered. Label each one: finding / hardening / informational.
     Include the raw evidence filename and the reproduction steps. -->

_None recorded yet._

---

## Tested and found clean

<!-- The bulk of the work. One row per endpoint with the control that defends it. -->

| Endpoint | Control |
| --- | --- |
| _tbd_ | _tbd_ |

---

## Not testable / blocked

<!-- Anything you could not reach, and precisely why -->

---

## Reportability (RoE filter)

| Item | RoE verdict |
| --- | --- |
| _tbd_ | _tbd_ |

---

## Artifacts

All under `recon/` (raw) and `runs/` (scanner output).

| File | Content |
| --- | --- |
| `{name}.RoE` | Rules of engagement — the scope record |
| _tbd_ | _tbd_ |

---

## Housekeeping

- Do not touch any host that is not explicitly in scope.
- Verify the rate limit and required header against the RoE before resuming.

---

## Next

1. _tbd_

## Change log

- **{today}** — Engagement scaffolded; RoE captured; enumeration started.
"""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def slugify(value: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "", value.lower())
    if not s:
        sys.exit(f"error: cannot derive a slug from {value!r}")
    return s


def fetch_roe(url: str) -> str:
    """Dump a URL to text with `links -dump`.

    The default output width is intentional: it wraps the rules-of-engagement
    panel so each label sits on its own line, which is what parse_roe() keys
    off. A wider width can merge labels and values onto one line.
    """
    if shutil.which("links") is None:
        sys.exit("error: `links` not found — install it, or pass --roe-file")
    try:
        proc = subprocess.run(
            ["links", "-dump", url],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        sys.exit(f"error: timed out fetching {url}")
    if proc.returncode != 0:
        sys.exit(f"error: links exited {proc.returncode}: {proc.stderr.strip()}")
    if not proc.stdout.strip():
        sys.exit(f"error: `links -dump` returned nothing for {url}")
    return proc.stdout


def write(path: Path, content: str, force: bool, dry_run: bool) -> str:
    """Write a file, refusing to clobber unless forced. Returns a status word."""
    if path.exists() and not force:
        return "skip (exists)"
    if dry_run:
        return "would write"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return "written"


def display(path: Path) -> str:
    """Path for humans: repo-relative when possible, absolute otherwise."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def read_sig() -> str:
    if not SIG_FILE.exists():
        sys.exit(f"error: signature not found at {SIG_FILE}")
    return SIG_FILE.read_text(encoding="utf-8").rstrip("\n")


def signed(body: str, sig: str) -> str:
    return body.rstrip("\n") + "\n\n```\n" + sig + "\n```\n"


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="newprog",
        description="Scaffold a new bug-bounty / VDP engagement folder.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-p", "--platform", default="intigriti", choices=PLATFORMS,
                   help="Bug bounty platform (default: intigriti).")
    p.add_argument("-n", "--name", required=True, metavar="SLUG",
                   help="Program / vendor slug, e.g. nexuzhealthwebpacs.")
    p.add_argument("--kind", default="bounty", choices=KINDS,
                   help="Engagement type (default: bounty).")
    p.add_argument("--roe-url", metavar="URL",
                   help="Program page to dump with `links -dump`.")
    p.add_argument("--roe-file", metavar="PATH",
                   help="Use a local RoE dump instead of fetching a URL "
                        "(for pages behind a login).")
    p.add_argument("--base", default="bug-bounties", metavar="DIR",
                   help="Base directory (default: bug-bounties).")
    p.add_argument("--force", action="store_true",
                   help="Overwrite managed files (never touches .RoE unless "
                        "--force and --roe-* re-fetches it).")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would be created, write nothing.")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if bool(args.roe_url) == bool(args.roe_file):
        sys.exit("error: pass exactly one of --roe-url or --roe-file")

    slug = slugify(args.name)
    target = REPO_ROOT / args.base / args.platform / slug
    roe_path = target / f"{slug}.RoE"

    # --- RoE -------------------------------------------------------------- #
    if args.roe_file:
        src = Path(args.roe_file).expanduser()
        if not src.exists():
            sys.exit(f"error: --roe-file not found: {src}")
        roe_text = src.read_text(encoding="utf-8", errors="replace")
        roe_origin = f"local dump: {src}"
    else:
        print(f"[*] fetching RoE: {args.roe_url}")
        roe_text = fetch_roe(args.roe_url)
        roe_origin = args.roe_url

    if not roe_text.strip():
        sys.exit("error: RoE is empty")

    facts = parse_roe(roe_text)

    # --- render ----------------------------------------------------------- #
    exclusions = ""
    if len(facts["cidrs"]) > 1:
        exclusions = (
            "\n- **CIDR ranges seen in the RoE** (in-scope and excluded — "
            "separate them carefully): "
            + ", ".join(f"`{c}`" for c in facts["cidrs"])
            + "\n"
        )

    scope_block = (
        "\n".join(f"- `{h}`" for h in facts["hosts"][:40])
        or "<!-- paste the asset table from the RoE -->"
    )
    if len(facts["hosts"]) > 40:
        scope_block += f"\n- … and {len(facts['hosts']) - 40} more (see the RoE)"
    if facts["cidrs"]:
        scope_block += "\n\nCIDR ranges in the RoE:\n" + "\n".join(
            f"- `{c}`" for c in facts["cidrs"]
        )

    wildcards = [h for h in facts["hosts"] if h.startswith("*")]
    if wildcards:
        wildcard_note = (
            "the RoE scope contains wildcard asset(s) "
            + ", ".join(f"`{w}`" for w in wildcards)
            + " — subdomain enumeration is in scope **within the stated IP "
              "range(s) only**. Both conditions must be met; a hostname alone "
              "is not enough."
        )
    else:
        wildcard_note = (
            "the RoE scope lists fixed assets and no wildcard — **do NOT run "
            "subdomain enumeration.** Anything found that way is out of scope."
        )

    ctx = dict(
        name=slug, platform=args.platform, kind=args.kind,
        today=date.today().isoformat(),
        rate_limit=_bullet(facts["rate_limit"], "**TBD — read the RoE**"),
        user_agent=_bullet(facts["user_agent"], "**TBD — read the RoE**"),
        request_header=_bullet(facts["request_header"], "**TBD — read the RoE**"),
        exclusions_block=exclusions, scope_block=scope_block,
        wildcard_note=wildcard_note,
    )

    agents_md = AGENTS_TEMPLATE.format(**ctx)
    readme_md = signed(README_TEMPLATE.format(**ctx), read_sig())

    # --- write ------------------------------------------------------------ #
    print(f"[*] target: {target}")
    print(f"    RoE source: {roe_origin}")

    if args.dry_run:
        print("[!] dry run — nothing written\n")
    results = []

    roe_status = write(roe_path, roe_text, args.force, args.dry_run)
    results.append((roe_path, roe_status))
    results.append((target / "AGENTS.md",
                    write(target / "AGENTS.md", agents_md, args.force, args.dry_run)))
    results.append((target / "README.md",
                    write(target / "README.md", readme_md, args.force, args.dry_run)))

    for sub in ("recon", "runs"):
        d = target / sub
        if args.dry_run:
            results.append((d, "would create"))
        else:
            d.mkdir(parents=True, exist_ok=True)
            results.append((d, "created"))

    width = max(len(display(p)) for p, _ in results)
    for path, status in results:
        print(f"    {display(path):<{width}}  {status}")

    # --- extracted-fact warnings ----------------------------------------- #
    print()
    for key, label in (("rate_limit", "rate limit"),
                       ("user_agent", "user agent"),
                       ("request_header", "required header")):
        if not facts[key]:
            print(f"[!] no {label} found in the RoE dump — set it by hand "
                  f"before testing")

    if facts["hosts"]:
        print(f"[i] {len(facts['hosts'])} candidate in-scope host(s) extracted "
              f"from the dump — VERIFY against the RoE scope section")
    if facts["cidrs"]:
        print(f"[i] CIDRs seen ({len(facts['cidrs'])}): "
              f"{', '.join(facts['cidrs'])} — separate in-scope from excluded")

    # --- kickoff ---------------------------------------------------------- #
    print("\n" + "=" * 72)
    print("Kickoff — scope Copilot to the folder and paste this:")
    print("=" * 72)
    print(f"""
    cd {display(target)}
    copilot

    Read {slug}.RoE in full — it is the only source of scope truth. Then
    enumerate the in-scope targets listed there, staying inside the RoE's
    rate limit and request-header rules, and write everything up in README.md
    following the house structure in AGENTS.md.

    Start with passive recon, then HTTP fingerprinting, then map the
    application surface. Record raw evidence under recon/ as you go. Do not
    touch anything the RoE does not explicitly list.
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
