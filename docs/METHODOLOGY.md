# Method

How these engagements are run. It is deliberately boring, because the interesting part of an AI red team is usually the backend code the agent was given, not the prompt.

## 1. Authorization before anything

Written scope, dedicated account, explicit statement of what is out of bounds. If an action could cross the boundary, it is not performed; it is raised as a question. No shared credentials, no other participants' sessions, no third-party infrastructure.

## 2. Enumerate the tool contract

The first hour is reconnaissance, and the target is not the chatbot — it is the tool list.

For every tool, record:

- exact name and parameter schema
- the description the model sees (this is the vendor's own statement of intent and trust boundary)
- what the tool actually returns on success and on failure
- which parameters look like identifiers, paths, prices, or identity

A tool that accepts a `session_id`, a `price`, a `file_name` or a `level` claim is a tool that has already told you where the authorization decision lives.

## 3. Map the data flow

```text
user text -> model -> tool arguments -> backend code -> side effect
```

The vulnerability is almost always at one of two joins:

- **text → tool argument**: the model is persuaded to place attacker data into a privileged parameter
- **tool argument → decision**: the backend treats that parameter as trusted

Find which join fails, and the finding writes itself. Findings that stop at "the model said something bad" are not findings.

## 4. One hypothesis per test

Each test changes a single variable and states, in advance, what result would confirm or refute it. This keeps the record honest and makes the report reproducible: a reviewer can replay a sequence and see the same transitions.

Where a helper script was used to send a request, it sent exactly one reviewed request, with the rationale and the raw response recorded. No scanners, crawlers, fuzzers or gate-probing loops — they produce noise, and noise cannot be turned into a root cause.

## 5. Prove it with a side effect

Chat text is a claim. Side effects are evidence:

- a unique canary hostname resolving from the target's egress
- a unique path appearing in the target's own request log, with a server-side timestamp
- a file read returning a value that could not have been guessed
- a state transition in a second, independent channel (UI after API, or the reverse)

A control that only suppresses the *response* does not suppress execution, egress, or writes. Test the side effect, then test whether it survives the filter.

## 6. Separate the three kinds of impact

Every finding is reported on three levels, and they are never blended:

| Category | Meaning |
|---|---|
| **Demonstrated** | Observed in this engagement, reproducible from the steps given |
| **Available but not exercised** | Reachable from a proven primitive, deliberately not run (destructive, unnecessary, or out of scope) |
| **Not tested** | Unknown; stated as unknown |

This is why several write-ups carry no CVSS score. A score implies inputs that were not established, and a number invented to look rigorous is worse than an honest qualitative rating.

## 7. Root cause, not payload

The payload is one instance. The report has to name the design defect that made it work, because that is the only thing a fix can target:

- capability model of a tool (what can this tool reach?)
- representation handling (what string is validated, and what string is used?)
- authorization source (who decides the principal — the session or the request?)
- state model (what is checked, and when is it re-checked?)

Then the remediation, then a regression test that fails before the fix and passes after. A finding without a test is a suggestion.

## 8. Mapping, only when it earns its place

CWE and OWASP LLM Top 10 categories are assigned when the causal relationship is demonstrable, and explicitly *not* assigned when it is not. Several of these levels are conventional backend defects wearing an agent interface — mapping them to prompt injection would misdescribe them and point the fix in the wrong direction.

## What is not done

- No public write-ups, solution repositories or payload collections during an engagement.
- No unreviewed automation, and no brute force against any gate.
- No probing outside the agreed boundary, however interesting the adjacent service looks.
- No fabricated or reconstructed evidence. Missing means missing.
