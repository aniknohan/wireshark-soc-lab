# Detection design | Repeated portal login failures followed by success

**Status** · Proposed correlation logic and test cases for future SIEM implementation.

## Required telemetry

Use normalized portal or identity-provider authentication events with event time in UTC, account ID, trusted client IP, application, outcome and event ID. Deduplicate by event ID. Normalize the account identifier according to the identity provider’s rules. Treat archive activity as enrichment from access or export audit logs.

## Logic

For each successful login, look back five minutes for at least three distinct failed login events for the same application, account and trusted client IP. Emit one alert per qualifying success event. Include timestamps, failure count, client IP and event IDs so an analyst can reproduce the match. Evaluate by event time and account for ingestion delay in the production implementation.

Check for archive activity in the five minutes after success. Treat export events as session-linked only when a trusted session or request correlation key supports the join. Without that key, record proximity by client IP and time separately.

| Test case | Expected result |
| --- | --- |
| Three failures followed by success for the same account, app and IP within five minutes | Alert |
| Two failures and success | No alert |
| Third failure occurs after success | No alert |
| Three failures followed by success for a different account | No alert |
| Oldest of three failures is outside the five-minute window | No alert |
| One failure event appears three times with the same event ID | No alert |
| User mistypes a password three times, then signs in successfully | Alert for analyst review |
| Archive event shares IP and time but has no trusted session key | Nearby archive activity only |

The reference PCAP illustrates the positive sequence at the HTTP layer. A live SIEM rule needs authentication events and validation against normal portal activity. Shared IPs, proxies, and repeated user mistypes can create ambiguous matches.
