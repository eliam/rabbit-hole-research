# Axel Springer SE / AS National Media & Tech — Intigriti Program Scope

Program: **Axel Springer SE/Axel Springer National Media & Tech**
Slug: `axelspringerse` — Public, Open — Media & Entertainment
Source: `axelspringerse.RoE`

## Rules of engagement

| Field | Value |
| --- | --- |
| Contact | @intigriti.me |
| User agent | Not applicable |
| Automated tooling | Not applicable |
| Request header | Not applicable |

Stated agreements for participation:

- Respect the Community Code of Conduct
- **Do not execute intrusive commands within production environments**
- Respect the scope of the program
- Do not disclose vulnerability information or PoCs without prior written consent
- Safe harbour for researchers is applied

### Worst-case scenarios (what the program cares about)

1. Publishing fake news on their website.
2. Obtaining sensitive user data.
3. Command execution on production services.

## Bounties

| Severity | CVSS | Tier 1 | Tier 2 | Tier 3 |
| --- | --- | --- | --- | --- |
| Low | 0.1–3.9 | €50 | €35 | €15 |
| Medium | 4.0–6.9 | €150 | €100 | €50 |
| High | 7.0–8.9 | €300 | €200 | €75 |
| Critical | 9.0–9.4 | €1,250 | €500 | €250 |
| Exceptional | 9.5–10.0 | €2,500 | €1,000 | €500 |

Stats: 2,908 submissions received, 631 accepted, avg payout €222.

## Assets — IN SCOPE

### Tier 1

| Asset | Type |
| --- | --- |
| politico.eu | URL |
| adtechnology.axelspringer.com | URL |
| *.asadcdn.com | Wildcard |
| bild.de | URL |
| welt.de | URL |
| epaper.welt.de | URL |
| cancellation.prod.ps.welt.de | URL |
| digital.welt.de | URL |
| signin.auth.welt.de | URL |
| m.bild.de | URL |
| *.hey.bild.de | Wildcard |
| go.welt.de | URL |
| *.auth.bild.de | Wildcard |
| *.sportbild.de | Wildcard |
| meinkonto.bild.de | URL |
| *.bild.tv | Wildcard |
| *.computerbild.de | Wildcard |
| dealer.prod.ps.axelspringer.de/purchases/* | Wildcard (path) |
| 18.184.198.198, 18.185.214.59, 18.194.109.179, 3.121.117.72, 3.121.138.10, 3.121.138.128, 3.121.138.134, 3.121.138.170, 3.121.138.33, 3.121.138.43, 3.124.248.208, 35.156.137.39 | IP Range |

### Tier 2

| Asset | Type |
| --- | --- |
| emarketer.com | URL |
| newsos.com | URL |
| *.germany.politico.eu | Wildcard |
| *.welt.de | Wildcard |
| *.bild.de | Wildcard |
| *.bild.design | Wildcard |
| *.autobild.de | Wildcard |
| *.bz-berlin.de | Wildcard |
| *.spring-media.de | Wildcard |
| *.springtools.de | Wildcard |
| editorial.one | URL |
| *.as-nmt.de | Wildcard |

### Tier 3

| Asset | Type |
| --- | --- |
| *.ein-herz-fuer-kinder.de | Wildcard |
| *.fitbook.de | Wildcard |
| *.myhomebook.de | Wildcard |
| *.petbook-magazine.com/ | Wildcard |
| *.petbook.de | Wildcard |
| *.stylebook.de | Wildcard |
| *.techbook.de | Wildcard |
| *.travelbook.de | Wildcard |
| *.wissen-sie-mehr.de | Wildcard |
| technik.autobild.de | URL |
| technik.beta.autobild.de | URL |

## OUT OF SCOPE

- `*.axelspringer.com` — Wildcard, explicitly out of scope
- All domains not listed as in scope

### General restrictions

- Duplicates marked as duplicate if already known.
- No realistic exploit scenario / attack surface → severity "None".
- Spam, social engineering, phishing not allowed (incl. luring victims to attacker domains).
- Software without security updates not considered.
- Physical access, MITM, compromised accounts not permitted.
- New critical/exceptional: out of scope first 7 days. High: first 14 days. Medium or lower: first 30 days.
- Submissions without PoC not considered.
- Same root cause (code/misconfiguration/dependency) = single submission.
- Not responsible for outgoing links.
- Authenticated endpoint: cache poisoning only accepted if valid with changing auth headers.
- IDOR on Hey chat with UUID is out of scope (risk accepted); enumerating/guessing those UUIDs is welcomed.

### Application exclusions

Credential disclosure w/o business impact; Pre-auth ATO/OAuth squatting; CORS on non-sensitive endpoints; low/no-impact CSRF; reverse tabnabbing; clickjacking w/o proven impact; CSV injection; session non-invalidation; tokens leaked to third parties; email spoofing/SPF/DMARC/DKIM; content injection without HTML modification; username/email enumeration; email bombing (self only); homograph attacks; XMLRPC enabled; files retaining metadata.

## FAQ notes

- No credentials provided; researchers may self-register accounts.
- Retests are sometimes requested, bonus up to €50.
