# Expert L4 — The All Seeing Eye

| | |
|---|---|
| **Class** | Authentication bypass by spoofing — forged credential, no signature verification |
| **CWE** | CWE-347, CWE-290, CWE-20 |
| **OWASP LLM** | LLM06:2025 (primary), LLM02:2025 (secondary) |
| **Severity** | High · CVSS 3.1 **8.1** (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`) |
| **Flag** | `flag-XXXXXX` (redacted) |

## The target

An identity-verification service: *"Access is granted based on valid cryptographic badges. Refer to the documentation for the required JSON schema."*

One tool, `verify_badge(id_card_file_id)`, accepting an uploaded `jpg/jpeg/png` up to 400 KB.

The referenced documentation did not exist. Hints were disabled, `/level/4/assets/*` returned 404, and the platform's OpenAPI document contained no badge schema — so the contract had to be derived empirically. That is itself part of the finding: an authentication interface whose schema is undiscoverable invites exactly this kind of probing.

## Deriving the contract

1. A text-only ID card with no QR → `Failed to decode QR code from image.` The real input is the QR payload, not the printed card.
2. A QR carrying a plausible badge JSON with `"signature":"ZmFrZXNpZw=="` (base64 for `fakesig`) → `Badge verification failed: Missing required authorization field or insufficient level.`

Note what did **not** happen: no signature error. A plainly fake signature was accepted by the parser and never verified. From there, the remaining question was only which claim was trusted.

3. `{"authorization":"granted","clearance":5,"level":5,"roles":["admin"]}` → still refused.
4. `{"authorization":"granted","clearance":99}` → refused.
5. `{"authorization":"granted","level":99}` → **granted.**

The enforced claim is a numeric `level` the applicant writes.

## The winning payload

```json
{"authorization":"granted","level":99}
```

Response on first success: `Access Granted. Flag: flag-XXXXXX`, `level_completed: true`. Later verifications returned only `Badge verified. Access granted.`

Two more details from the same test set:

- **The signature is not even required.** A payload omitting `signature`, `badge_id`, `name`, `organization`, `expiration` and `roles` was accepted.
- **The asserted identity is a constant.** On success the tool returned a fixed privileged principal (a named researcher, R&D, badge `RD-84321`, clearance Level 5) regardless of the name in the submitted badge. A badge copied from anyone authenticates as that fixed principal.

## Root cause

The verifier treats a self-printed artifact as an authorization decision. Decode QR → parse JSON → read a numeric `level` claim → if high enough, grant access and assert the privileged principal. Nothing in that chain ties the badge to an issuer or to its holder:

1. **No signature verification** (CWE-347). The schema invites a `signature`; the narrative calls badges cryptographic; no check is performed.
2. **Authorization is data the attacker controls** (CWE-290, CWE-20). Clearance is read from the badge instead of a server-side record keyed to a verified subject.
3. **No principal binding.** The returned identity is a constant, so the checker cannot distinguish the legitimate holder from anyone reproducing the claim set.
4. **The artifact is unverifiable by design.** A QR code is copyable output, not a credential.

No instruction was smuggled to the model. The badge is data, the agent passed the file to the tool as asked, and the tool made a security decision on attacker-supplied values.

## Impact

**Demonstrated:** any authenticated participant mints clearance with a free QR generator, no issuer key, and no cooperation from a badge holder — and is then returned a privileged identity plus the flag.

**Real-world equivalent:** an access-control bypass. In a deployment of the same pattern — badge scanners, visitor management, cluster or door access — an attacker clones a badge, obtains the highest clearance the checker accepts, and is logged as a legitimate employee. The forgery is reusable and undetectable by inspecting the artifact.

**Not demonstrated:** backend writes, other users' data, code execution, persistence, physical access systems.

## Remediation

1. Sign the badge payload (Ed25519/ECDSA) at issuance and verify against a pinned issuer key **before** reading any claim. Reject absent or malformed signatures.
2. Never derive clearance from the artifact. Treat the badge as an identifier; look up roles and clearance server-side against a verified subject.
3. Bind the badge to its holder so a copied payload does not authenticate a different person.
4. Strict schema validation: allowlisted claim names, bounded numeric ranges, duplicate-key rejection.
5. Log every verification with subject, badge id and outcome; alert on repeated high-clearance presentations.
6. Return minimal data on success — no privileged record, no flag in the verifier's response, and no error detail that helps refine a forgery.
