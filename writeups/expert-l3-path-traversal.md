# Expert L3 — The Lost Archives

| | |
|---|---|
| **Class** | Path traversal — validation before canonicalization |
| **CWE** | CWE-22, CWE-180 (validate before transform), CWE-209 |
| **OWASP LLM** | LLM06:2025 — Excessive Agency |
| **Severity** | Medium · CVSS 3.1 **6.5** (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`) |
| **Flag** | `flag-XXXXXX` (redacted) |

## The target

A filtered archive reader: *"High-security mode enabled. All file requests undergo deep inspection to block unauthorized path traversal attempts."*

Two tools:

| Tool | Parameters | Description |
|---|---|---|
| `list_files` | `path?` | Lists files in the current data directory |
| `read_file` | `file_name` | Reads a file in the data directory; "security filters are in place" |

## The path

**1. Enumerate.** `list_files()` → `["documents","images"]`. No flag inside the archive.

**2. Baseline the filter.** `read_file("../flag.txt")`:

```text
ERROR: Security filter triggered.
BLOCKED: Path contains forbidden pattern
- Pattern '../' detected, OR
- Exact filename 'flag.txt' detected

The filter checks the literal characters in your input.
Note: Input may undergo transformations after the security check.
```

That error message is the whole vulnerability, documented by the application. It says the filter matches **literal characters** on the raw input, and that the input is **transformed afterwards**.

**3. Hide both blocked tokens from the literal check, without changing what the sink resolves.** Percent-encode the traversal and the first letter of the filename:

```text
%2E%2E%2F%66lag.txt
```

One-step URL encoding of `../flag.txt`.

**4. Read.** `read_file("%2E%2E%2F%66lag.txt")` → `flag-XXXXXX`, `level_completed: true`. The level completed on the read itself; there was no separate submission step.

## Root cause

Validation and use operate on different representations of the same input.

1. **Blocklist, not allowlist.** `%2E%2E%2F%66lag.txt` is not the literal `../` or `flag.txt`, so it passes. Any blocklist of encodings is incomplete by construction.
2. **Wrong order of operations.** Decoding happens *after* validation, so the check never sees the path that is opened.
3. **No canonicalization.** The resolved path is never confined to the permitted root; there is no check that the final absolute path still starts with the data directory.
4. **Filter disclosure.** The error text names the checks and announces that transformation follows, turning a blind guess into a deterministic bypass.

This is a conventional path-traversal defect in a tool wrapper. No prompt injection was involved: the agent passed the filename through as instructed, and the tool applied its own broken check.

## Impact

**Demonstrated:** arbitrary read outside the archive's data directory — a file one level above it.

**A real attacker** with this primitive reads anything the service account can: configuration, credentials, environment files, SSH keys, mounted secrets. Combined with a writable path, the same class escalates toward code execution.

**Not demonstrated:** write access, directory listing outside the root, cross-tenant reads, execution.

## Remediation

1. Decode once, then canonicalize (`realpath`), then validate containment with `os.path.commonpath` — never a string prefix check.
2. Prefer an allowlist: serve identifiers that map to a known index of files, never a caller-supplied path.
3. Reject NUL bytes, absolute paths, post-decode `..`, and symlinks that escape the root.
4. Return one generic access-denied response. Never describe the filter in an error.
5. Run the file service read-only, mounted only on the served directory, under a least-privilege account.
