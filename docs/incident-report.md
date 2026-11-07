# Reference incident report

**Case WS-001** · Simulated internal portal investigation · Network evidence only

## Disposition

Escalate for validation as possible account compromise. The same client made three rejected attempts for the same demo account, then the portal accepted a login and transmitted a ZIP shortly afterward. The 404 response to the payroll request contained a short error message.

## Evidence timeline

All offsets are relative to frame 1 of the synthetic reference capture. Client is `192.0.2.10` and portal is `192.0.2.20:8080`. Client port identifies each conversation within this capture.

| Response time | Client port | Request → response frames | Observation |
| --- | --- | --- | --- |
| +0.040 s | 49152 | 4 → 5 | `GET /health` → 200, baseline response |
| +2.040 s | 49153 | 13 → 14 | `POST /login` → 401 |
| +4.040 s | 49154 | 22 → 23 | Same account → 401 |
| +6.040 s | 49155 | 31 → 32 | Same account → 401 |
| +8.040 s | 49156 | 40 → 41 | `POST /login` → 200, body says `demo login accepted` and response sets a demo cookie |
| +10.040 s | 49157 | 49 → 50 | `GET /exports/inventory.zip` → 200 with ZIP body |
| +12.040 s | 49158 | 58 → 59 | `GET /exports/payroll.zip` → 404 with `missing` body |

## Recovered artifact

The reference response body contains a ZIP with `inventory.txt`. Its SHA-256 is `60b35d3ce7a8f6228a5921fde92978e1fd4dd62f759a9fa6171f1b2965265f47`. Hashing the exported body tests whether the recovered bytes match the reference object.

## Assessment and handoff

The packets show repeated failures, successful authentication as reported by the demo portal, and an archive response sent to the same IP. The export request carries no session cookie, so the packet sequence alone cannot link the archive to the successful session. The source IP is a network endpoint and cannot establish who initiated the traffic. The archive’s presence on the wire also cannot establish whether it was saved or opened.

Correlate portal access logs and authentication events by time, account, client IP, and any request or session IDs. Validate authorization for the export and check for similar sequences from other clients. If the application logs confirm unauthorized access, revoke the affected session and follow the account containment process. For a detection exercise, correlate repeated failures and a subsequent success for the same account within a short window, then enrich with export events. Test against legitimate mistyped passwords before treating the alert as confirmed compromise.
