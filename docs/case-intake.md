# SOC case intake | WS-001

| Field | Value |
| --- | --- |
| Environment | Simulated internal HTTP portal. Reference capture uses documentation addresses. Ubuntu replay uses loopback. |
| Queue | SOC Tier 1 → Tier 2 / application owner |
| Trigger | Repeated rejected sign-ins followed by a successful sign-in and nearby archive activity |
| Initial priority | Medium in this exercise. Verify access and sensitivity before raising priority. |
| Scope | One capture, one client endpoint, one portal, seven TCP conversations |
| Investigation objective | Determine what the portal sent and whether the available evidence links the download to the successful login. |
| Reference disposition | Escalate for validation. Authorization and session attribution remain open. |

## Triage and decision gates

| Gate | Evidence required | Action |
| --- | --- | --- |
| Validate the alert | Same client, same account, rejected attempts followed by an accepted login | Record frames and request/response pairings. Review benign explanations such as repeated mistypes. |
| Scope file activity | Request path, response code and body, recovered object hash | Report inventory ZIP delivery and payroll 404 separately. |
| Establish session linkage | Portal access logs with trusted session or request correlation | Ask the application owner to confirm which session made the export. Preserve timestamps and normalize to UTC before joining logs. |
| Determine authorization | Account owner confirmation, entitlement and export audit records | Confirm whether the inventory export was expected. Raise priority if unauthorized access or sensitive data exposure is substantiated. |
| Decide containment | Verified account or session scope and incident owner approval | If unauthorized activity is confirmed, coordinate session revocation and evidence preservation under the incident process. |

For a real case, ask the portal owner for authentication outcome, account ID, trusted client address, request ID, session identifier or approved correlation token, export path, response status, and entitlement result. Ask the endpoint team for supporting host activity only after the client identity is scoped.

## Reference handoff

The reference capture shows three failures, a successful demo login, an inventory ZIP response, and a payroll 404. The export request carries no session cookie. Tier 2 should verify account ownership, export authorization and session correlation. Use the [reference report](incident-report.md) for frame citations and the [evidence register](../evidence/register.md) for provenance.
