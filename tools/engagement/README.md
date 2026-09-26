## Engagement workflow

1. **Scaffold the folder.** One command creates the directory, dumps the RoE
   with `links -dump`, and drops in a starter `README.md` plus an `AGENTS.md`:

   ```bash
   tools/engagement/newprog.py -p intigriti -n <program-slug> [--kind vdp] \
       --roe-url 'https://app.intigriti.com/researcher/programs/.../detail'
   ```

   For program pages behind a login, dump the page from an authenticated
   browser session and pass it with `--roe-file`. Use `--dry-run` first if you
   want to see the plan. **Always eyeball the resulting `.RoE`** — if `links`
   hit a login wall, you will have captured the login page instead.

2. **Verify the extracted rules.** The RoE panel (rate limit, user agent,
   required request header, exclusions, scope assets) is parsed out of the dump
   and written into both `AGENTS.md` and the README, flagged for verification.
   A misread rate limit or a missed required header invalidates the engagement.

3. **Scope a session to the folder and start.**

   ```bash
   cd bug-bounties/intigriti/<program-slug>
   copilot
   ```

   Copilot reads `AGENTS.md` from the working directory, so the engagement
   rules, evidence layout, README structure, and scope discipline apply
   automatically. The scaffolder prints the kickoff prompt.

4. **Work the RoE's targets**, writing raw evidence to `recon/` and the
   write-up to `README.md` as you go.

## Conventions

- **The RoE is the only source of scope truth.** If anything else disagrees
  with it, the RoE wins.
- **Scope discipline.** Test only what the RoE lists. Do not run subdomain
  enumeration unless the scope is wildcard-based *and* the conditions are met —
  for a fixed host list it is pure scope creep.
- **Every README ends with the signature block** from `sig.txt`, fenced so
  markdown does not collapse it onto one line:

  ````
  ```
  (\_/)
  (o.o)
  (> <) rabbit-hole-research
  ```
  ````

- **Prove negatives.** Document how each control was ruled out, not just that
  it was.
- **Apply the RoE's out-of-scope list before calling something a finding.**

```
(\_/)
(o.o)
(> <) rabbit-hole-research
```
