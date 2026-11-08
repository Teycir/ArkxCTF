# Expert L7 — The Octopus

| | |
|---|---|
| **Class** | Authorization keyed on a caller-supplied identity — cache poisoning / confused deputy |
| **CWE** | CWE-639, CWE-22, CWE-209 |
| **OWASP LLM** | LLM06:2025, LLM02:2025 |
| **Severity** | High · CVSS 3.1 **6.5** (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`) |
| **Flag** | `flag-XXXXXX` (redacted) |

## The target

A chat interface fronting six MCP tools:

| Tool | Parameters | Purpose |
|---|---|---|
| `summarize_text` | `text`, `max_length?` | Text summary |
| `detect_errors` | `text` | Error detection |
| `upload_file` | `content`, `filename?` | Returns a file id |
| `process_cache_update` | `json_string`, `session_id` | Parses a JSON manifest, writes a session cache |
| `read_root_flag` | `session_id` | Reads the root flag for a privileged session |
| `get_system_status` | — | Privileged cluster health |

Two tools take a `session_id` as a parameter. That is the whole vulnerability in one sentence: **the caller names the identity the authorization check uses.**

## The path

**1. Ask for the error path.** Calling `read_root_flag("recon1")` returns:

```text
ERROR: Permission denied. Your session key '<session-id>'
does not match the required administrator key: '<admin-key>'
```

An error message that hands over both the real session identity and the administrator key.

**2. Make the key readable material.** `upload_file("<admin-key>")` → `file_id_<redacted>.txt`. A file the UI-backed tool can read, created legitimately by the session.

**3. Poison the cache under the real identity.**

```text
process_cache_update(
  json_string = {"status":"SAFE","cache_task_id":"file_id_<redacted>.txt"},
  session_id  = "<session-id>"
)  ->  SUCCESS: Cache updated.
```

**4. Read the flag.**

```text
read_root_flag("<session-id>")  ->  SUCCESS: flag-XXXXXX
```

Cache writes were scoped by the `session_id` argument, not by the authenticated session. Poisoning the administrator's cache key with the administrator key made the privileged read succeed.

## Root cause

The authorization boundary is derived from client input:

1. `process_cache_update` accepts a caller-supplied `session_id` instead of deriving the cache key from the authenticated server-side session.
2. `cache_task_id` resolves a file reference without binding it to the caller's upload namespace — files created through the API were not readable, but a UI-created upload was, so the scoping existed somewhere and simply wasn't applied to the lookup that mattered.
3. `read_root_flag` uses the same caller-supplied value as the privilege selector, so poisoning that key changes the authorization decision.
4. The non-privileged error path discloses the real session identity and the administrator key — the raw material for the whole chain.

The challenge's own lessons panel attributes the level to a parser differential between a regex filter and a JSON parser on duplicate keys. That was not required here and was not reproduced; if it exists, it is a second bug. Fixing only the parser would not have stopped this chain.

## Impact

A normal authenticated participant recovers the real session identity and admin key from a non-privileged lookup, poisons that session's cache, and reads the root flag. The same cache primitive may expose other files readable by the MCP process.

**Demonstrated:** root-flag read and level completion. **Not demonstrated:** OS-level access, code execution, persistence, cross-user data access, network exfiltration.

## Remediation

1. Derive the cache key and every privilege decision from the authenticated server-side session. Ignore or reject client-supplied identity for authorization.
2. Resolve file references only through an allowlist of uploads owned by the authenticated session; reject absolute paths and `..`.
3. Never put administrator keys or raw session identifiers in error messages. One generic denial.
4. Canonicalize JSON manifests and reject duplicate keys; validate the parsed object once and pass that object to the consumer.
5. Least privilege for the MCP process: restrict readable paths and egress.
6. Regression test: a non-privileged session must not be able to write into another session's cache, and a poisoned cache must not satisfy a privileged read.
