# ArkxCTF — AI Red Team Field Notes

Eight hands-on AI-agent security challenges, eight different ways an agent's **tools** failed. These are condensed write-ups from an authorized CTF engagement, published so security teams can see how agentic systems break in practice.

Every result here was reproduced by hand, one hypothesis at a time. Flags are redacted. No client, employer, or platform-internal material is included.

> **The recurring lesson:** in almost none of these levels was the model tricked. The model did what it was told. The weakness was in the contract around it — a tool that trusted its arguments, a filter that inspected the wrong string, an authorization decision derived from caller input.

## Why this matters

If you ship an LLM agent, your attack surface is not the prompt. It is the set of capabilities you handed the model: file readers, shell wrappers, MCP resources, payment tools, identity checks. Those tools are ordinary backend code with an unusually creative caller.

This repository is a catalogue of what that looks like when it goes wrong — with root cause, impact, CWE/OWASP mapping, and a fix for each.

## Results at a glance

| Track | Level | Challenge | Failure mode | CWE | OWASP LLM | Severity |
|---|---|---|---|---|---|---|
| Advanced | L5 | Bad Robot | `eval()` behind a calculator → file read via error text | CWE-95 | LLM06 | High · 7.7 |
| Advanced | L7 | Master of Resources | MCP server exposes a protected resource as a readable URI | CWE-284/200 | LLM02, LLM06 | Medium · 6.5 |
| Advanced | L9 | Blind Network Ninja | Shell injection under output suppression → OOB exfiltration | CWE-78, CWE-201 | LLM06 | High |
| Expert | L3 | The Lost Archives | Path traversal: validate before decode | CWE-22, CWE-180 | LLM06 | Medium · 6.5 |
| Expert | L4 | The All Seeing Eye | Badge forgery: clearance read from attacker-controlled claims | CWE-347, CWE-290 | LLM06, LLM02 | High · 8.1 |
| Expert | L6 | The Shape Shifter | Unsafe YAML deserialization → OS command execution | CWE-502 | LLM03 | High |
| Expert | L7 | The Octopus | Tool authorization keyed on a caller-supplied session id | CWE-639, CWE-22, CWE-209 | LLM06, LLM02 | High · 6.5 |
| Expert | L8 | The Heist | Caller-supplied price + no balance re-check at execution | CWE-472, CWE-840 | LLM03 | Medium · 6.5 |

## Read the write-ups

| Write-up | What it shows |
|---|---|
| [Advanced L5 — Bad Robot](writeups/advanced-l5-bad-robot.md) | A calculator tool that is really `eval()`, and an output filter that only guards the return value |
| [Advanced L7 — Master of Resources](writeups/advanced-l7-master-of-resources.md) | What "we put it behind a tool" looks like when the resource itself is addressable |
| [Advanced L9 — Blind Network Ninja](writeups/advanced-l9-blind-network-ninja.md) | Blind command injection, and how a platform's own request log becomes the exfiltration sink |
| [Expert L3 — The Lost Archives](writeups/expert-l3-path-traversal.md) | A traversal filter that checks the encoded string and opens the decoded one |
| [Expert L4 — The All Seeing Eye](writeups/expert-l4-badge-forgery.md) | "Cryptographic badge" verification with no signature check and a clearance claim you can write |
| [Expert L6 — The Shape Shifter](writeups/expert-l6-yaml-deserialization.md) | Configuration YAML that constructs Python objects, then runs commands |
| [Expert L7 — The Octopus](writeups/expert-l7-tool-authorization.md) | Cache poisoning across a tool boundary, seeded by an error message that leaks the admin key |
| [Expert L8 — The Heist](writeups/expert-l8-price-tampering.md) | Business logic: the order price came from the caller, the balance was never re-checked |

## The four patterns worth remembering

**1. Attacker data becomes a decision.** Clearance from a badge claim, an order price from the request, a session identity from a tool argument. Anywhere untrusted data selects a privilege level, you have an authorization bypass waiting to happen.

**2. Filters inspect a different representation than the sink uses.** Blocklists on raw strings, checks on the encoded path, regex on JSON before a parser reads it. Canonicalize first, validate the canonical form, and pass the validated object forward.

**3. Suppressing output is not a control.** A tool that answers only `Online`/`Offline` still executes. Side effects — DNS lookups, request logs, file writes — are the real channel. Egress filtering is the control.

**4. Tool descriptions are documentation of your trust boundary.** "Returns a simple status code", "validates security badge", "reads the root flag if the session is privileged" — each is a promise the backend has to actually keep.

## Method

A short version of how these were run is in [docs/METHODOLOGY.md](docs/METHODOLOGY.md): enumerate the tool contract, map where user text becomes a tool argument, change one thing per test, and prove behaviour with a side effect rather than a sentence in the chat window. Findings are split into **demonstrated**, **available but not exercised**, and **not tested** — the distinction is the difference between a credible report and a wish.

Cross-level mapping, including what I deliberately did **not** map: [docs/OWASP-LLM-MAPPING.md](docs/OWASP-LLM-MAPPING.md).

## Scope and disclosure

- All testing was performed inside an authorized CTF instance, against a dedicated account.
- Only the platform's own interface and its documented HTTP endpoints were used.
- No public write-ups, payload collections, or third-party tooling were used.
- Flags are redacted (`flag-XXXXXX`). Session identifiers and any credential-shaped strings are redacted.
- No assessment workspace, private notes, or client material is published here.

## Work with me

I do AI red teaming for teams shipping agents, MCP servers, and LLM-backed products.

**What I can help with**
- Pre-launch red team of an agent or assistant: tool boundaries, prompt injection, data exfiltration paths
- MCP server and tool-contract review: what the model can reach, and what happens when it reaches it
- RAG and multi-tenant isolation reviews: cross-tenant retrieval, citation leakage, ACL bypass
- Threat modelling for agentic workflows, plus remediation and regression tests your CI can run
- Clear reports your engineers can act on: reproduction, root cause, impact, fix — no CVSS theatre

**How an engagement runs**
1. Scoping call: targets, boundaries, what "done" means.
2. Recon and threat model of the tool surface.
3. Testing, one hypothesis at a time, with evidence you can replay.
4. Report, walkthrough, and remediation review.

**Get in touch:** [github.com/Teycir](https://github.com/Teycir) — open an issue in this repo or send a DM. Tell me what you're building and what worries you about it.

## Repository layout

```text
README.md                  This page
writeups/                  One file per level
docs/METHODOLOGY.md        How the testing was run
docs/OWASP-LLM-MAPPING.md  Cross-level classification and mapping
```
