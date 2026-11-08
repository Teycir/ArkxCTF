# Advanced L7 — Master of Resources

| | |
|---|---|
| **Class** | Protected data modelled as a readable MCP resource |
| **CWE** | CWE-284 (improper access control), CWE-200 (exposure) |
| **OWASP LLM** | LLM02:2025 — Sensitive Information Disclosure (primary), LLM06:2025 |
| **Severity** | Medium · CVSS 3.1 **6.5** (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`, estimate) |
| **Flag** | `flag-XXXXXX` (redacted) |

## The target

A "managed resources" level whose browser UI was unavailable. The interface that mattered was still there: an MCP endpoint at `/level/7/mcp`, speaking streamable HTTP with SSE-framed JSON-RPC.

The lesson is not that the UI was broken. It is that the UI was never the boundary.

## The tool contract

After `initialize` and `notifications/initialized`, `resources/list` returned two literal URIs — no templates:

- `resource://flag` (name `get_flag`)
- `resource://super-secret`

Tools: `unlock_flag`, taking no arguments. Prompts: none.

## The path

1. `resources/read resource://flag` → `flag is locked`
2. `resources/read resource://super-secret` → a decoy
3. `tools/call unlock_flag {}` → `Flag has been unlocked!`
4. `resources/read resource://flag` → `flag-XXXXXX`
5. Submit → `{"success":true,"level_completed":true}`

The gate was a zero-argument tool with no privilege check, and the resource read path did not enforce state at all. Unlock state was per MCP session: a fresh `initialize` returned the resource to locked even after the level was marked complete — which confirms the state machine lives in the session, not in an authorization layer.

## Root cause

Two design errors compounded:

1. **The secret is addressable.** A protected value was published in the MCP catalogue as a first-class resource. Listing is discovery; reading is one message away.
2. **The control is advisory.** `unlock_flag` is self-service, takes no principal, and the resource reader never checks whether the caller was entitled to the value it returns.

Nothing here needed a clever prompt. The MCP client simply asked the server for what the server offered.

## Impact

Any session that completed the handshake could read the protected resource. In a real deployment this pattern leaks secrets to any connected client — including an agent that was manipulated elsewhere and now has a catalogue of readable URIs.

## Remediation

- Never model secrets as MCP resources. Resources are a publication surface, not a permission system.
- Enforce authorization **at read time**, per resource, against the authenticated principal — not at "unlock" time.
- Make unlock state server-side and bound to the session identity, and re-check on every read.
- Log resource reads with principal and outcome; alert on enumeration followed by reads.
- If a decoy is used, do not place it in the same namespace as the real asset: it advertises the shape of the target.
