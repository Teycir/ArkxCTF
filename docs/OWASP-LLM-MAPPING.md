# Cross-level classification

One table for the whole set, including the mappings that were deliberately **not** made.

| Level | Primary class | CWE | OWASP LLM 2025 | Severity |
|---|---|---|---|---|
| Advanced L5 — Bad Robot | `eval()` injection behind a calculator tool | CWE-95 | LLM06 Excessive Agency | High · 7.7 |
| Advanced L7 — Master of Resources | Protected value published as a readable MCP resource | CWE-284, CWE-200 | LLM02 (primary), LLM06 | Medium · 6.5 |
| Advanced L9 — Blind Network Ninja | Shell injection, output suppressed, OOB exfiltration | CWE-78, CWE-201 | LLM06 | High |
| Expert L3 — The Lost Archives | Path traversal, validate before decode | CWE-22, CWE-180, CWE-209 | LLM06 | Medium · 6.5 |
| Expert L4 — The All Seeing Eye | Forged badge, no signature check, clearance from claims | CWE-347, CWE-290, CWE-20 | LLM06 (primary), LLM02 | High · 8.1 |
| Expert L6 — The Shape Shifter | Unsafe YAML deserialization to command execution | CWE-502 | LLM03 | High |
| Expert L7 — The Octopus | Authorization from caller-supplied session id | CWE-639, CWE-22, CWE-209 | LLM06, LLM02 | High · 6.5 |
| Expert L8 — The Heist | Caller-supplied price, no execution-time balance check | CWE-472, CWE-840 | LLM03 | Medium · 6.5 |

## Why LLM06 dominates

Six of the eight are Excessive Agency, and that is not a coincidence — it is what happens when the same design shortcut is repeated: a tool is granted more capability than the task needs, and its arguments are trusted because they came from "our own agent".

The model is not the boundary. The tool is. If a calculator can open files, an archive reader can leave its root, or a verification tool can grant clearance, no amount of prompt hardening changes the outcome.

## Why LLM01 is absent

No level here was solved by getting an instruction past the model.

- **L5** — the operator typed directly into the calculator. No instruction was smuggled.
- **L3, L4, L7, L8** — the agent faithfully relayed the requested filename, badge, session id or price. The backend made the security decision on attacker data.
- **L6** — an instruction-shaped YAML string was refused or echoed as data; the successful payload was a deserialization tag, not a jailbreak.

Mapping those to prompt injection would be a category error, and the fix would land in the wrong layer. Prompt injection is a real and separate problem; it is just not the one these eight levels demonstrate.

## Where a second category applies

- **L4, L7** also map to LLM02 (Sensitive Information Disclosure): the verifier returns a privileged identity record; the error path returns the admin key.
- **L9** touches CWE-201 because the exfiltration used the application's own sent data — the flag left in a query string.
- **L8** is integrity-only (`C:N/I:H/A:N`). It is a ledger problem, not a disclosure one.

## Severity discipline

Scores are reported only where the inputs to a vector were established. Three levels carry no CVSS: the authentication and privilege context was not pinned down well enough to defend a number. A qualitative "High" with a stated rationale is more useful than a precise score that nobody can reproduce.

Where a vector metric is contestable — L5's `S:C`, for instance, because the vulnerable tool sits in a different authority than the filesystem it reads — the alternative reading and its score are stated in the write-up rather than left out.
