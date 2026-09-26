# AGENTS.md — rivianbugbounty engagement (intigriti, bounty)

Standing instructions for any Copilot session scoped to this folder.

## Read this first

The single source of scope truth is **`rivianbugbounty.RoE`** in this directory. Read it
in full before touching anything, and re-read the scope and out-of-scope
sections before making any claim about a finding. If anything below disagrees
with the RoE, **the RoE wins**.

## Rules of engagement (extracted from the RoE — VERIFY BEFORE TESTING)

- **Rate limit**: **TBD — read the RoE**
- **User agent**: **TBD — read the RoE**
- **Required request header**: X-Intigriti-Username: <Your Username>
- No DoS/DDoS, no brute force, no credential stuffing.
- No spam, social engineering, or physical intrusion.
- Safe harbour applies.

> Verify every line above against `rivianbugbounty.RoE` yourself. A misread rate limit or
> a missed required header invalidates the engagement.

## Scope discipline (hard rule)

- Test **only** assets the RoE explicitly lists. If it is not listed, it is out
  of scope — the RoE almost always says so in as many words.
- **Do not enumerate subdomains** unless the RoE scope is wildcard-based (e.g.
  an explicit `*.example.com` asset). For a fixed list of hosts, subdomain
  enumeration is scope creep and produces nothing but out-of-scope targets.
- **RoE check**: the RoE scope contains wildcard asset(s) `*.rivian.com` — subdomain enumeration is in scope **within the stated IP range(s) only**. Both conditions must be met; a hostname alone is not enough.
- Never follow redirects off an in-scope host without stopping to check whether
  the destination is in scope.
- If a scan is owed to another machine, never assume it is finished — ask.

## Evidence layout

| Path | Contents |
| --- | --- |
| `recon/` | raw responses, dumps, probe output, decoded artefacts |
| `runs/<timestamp>/` | scanner output (masprobe etc.) — see `tools/enum/masprobe.py` |
| `README.md` | the deliverable; findings live here |
| `rivianbugbounty.RoE` | never edit — it is the scope record |

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
(\_/)
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
