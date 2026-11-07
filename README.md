# Wireshark SOC Lab | Login Attempts and Archive Transfer

A simulated SOC investigation of an internal portal. The alert describes repeated login failures followed by a successful login and a possible file transfer. The analyst must reconstruct the sequence, verify which object crossed the network, and decide what to escalate.

**Skills demonstrated** — Packet triage, TCP stream reconstruction, HTTP analysis, evidence hashing, timeline building, and escalation writing.

## Start here

1. Open [reference.pcap](captures/reference.pcap) in Wireshark with **File → Open**. This is a deterministic, synthetic capture using documentation IPs and fake credentials.
2. Work through the [Wireshark walkthrough](docs/walkthrough.md) before opening the example report.
3. Use the [Ubuntu replay guide](docs/replay.md) to capture real TCP traffic from the same simulated case inside your VM. Add screenshots from your run and cite those frame numbers separately.
4. Compare your conclusions with the [reference incident report](docs/incident-report.md). Use the interview prompts to practice explaining your evidence.

## Case summary

| Observation | Evidence in reference PCAP |
| --- | --- |
| Same client submitted three failed logins | HTTP 401 at frames 14, 23, 32 |
| Portal indicated successful authentication | HTTP 200 and demo session cookie at frame 41 |
| Server transmitted an inventory archive | HTTP 200 at frame 50, ZIP body matches reference SHA-256 |
| Payroll request returned an error | HTTP 404 at frame 59, response body reads `missing` |

The sequence warrants investigation as a possible account compromise. The capture establishes what crossed the wire. Confirming user intent, session linkage, and authorization requires additional evidence.

## Repository contents

| Path | Purpose |
| --- | --- |
| `captures/reference.pcap` | Offline investigation, 63 Ethernet frames |
| `evidence/reference-inventory.zip` | Expected bytes for comparing your Wireshark export |
| `evidence/SHA256SUMS` | Integrity manifest for the reference files |
| `docs/` | Analysis steps, VM replay, sample analyst report |
| `scripts/lab.py` | Python standard-library reference generator and loopback replay |

From the repo root, verify the bundle with `sha256sum -c evidence/SHA256SUMS`. Regenerate the fixture with `python3 scripts/lab.py reference`.

The project adapts the source lab’s display filters, stream reconstruction, HTTP object export, and hashing into an original simulated investigation. [Wireshark User’s Guide — Following Protocol Streams](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
