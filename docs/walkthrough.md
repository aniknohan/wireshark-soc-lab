# Investigate the alert in Wireshark

**Alert brief** — A portal client made several failed login attempts and later requested two archives. Determine the endpoints, authentication outcome, and which response contained a ZIP.

Open the reference capture and use the display filter bar above the packet list. Press Enter after each filter. Clear the previous filter between steps.

| Step | Display filter | What to inspect |
| --- | --- | --- |
| 1. Establish scope | `tcp.port == 8080` | Expand IPv4 and TCP in packet details. Record who initiates the connection and which port the server listens on. |
| 2. Identify login requests | `http.request.method == "POST" && http.request.uri == "/login"` | Count requests. Right-click a matching row and choose **Follow → TCP Stream** to see the form body and server reply together. |
| 3. Validate authentication outcomes | `http.response.code == 401 || http.response.code == 200` | A 200 can mean many things. Follow the login stream and look for the response body and Set-Cookie header. |
| 4. Scope archive requests | `http.request.uri contains "/exports/"` | Follow both streams separately. Compare paths, response status, content type, and response body. |
| 5. Return to specific evidence | `frame.number == 50` | Inspect the response serving the inventory archive. |

If HTTP filters return no packets, select a TCP packet on port 8080 and use **Analyze → Decode As** to set TCP port 8080 to HTTP. In the packet list, the source and destination tell you who sent that particular frame. A TCP stream groups all packets in one connection, including both the request and the response. If following a stream replaces your filter, clear the filter before moving on.

## Recover the transferred object

1. Clear the display filter. Open **File → Export Objects → HTTP**.
2. Choose the `inventory.zip` object associated with the archive response. Save it as `inventory-exported.zip` outside the repo. If multiple objects appear, use the content type and packet number to select the response.
3. From the repo root on Ubuntu, run the commands below. Compare the hashes and record the filename inside the archive. Use the bundled archive as the comparison file.

```bash
sha256sum /path/to/inventory-exported.zip evidence/reference-inventory.zip
unzip -l /path/to/inventory-exported.zip
```

If the HTTP export list is empty, confirm that Wireshark is decoding port 8080 as HTTP, clear the display filter, and reopen the export dialog. The replay capture may split the headers and body across TCP segments, so the frame holding the decoded response may differ from the first segment.

## Build your own evidence

Use **View → Time Display Format → Seconds Since Beginning of Capture** for a consistent relative timeline. Record frame numbers, endpoints, event descriptions and the matching filters.

| Screenshot filename | What to show |
| --- | --- |
| `01-login-attempts.png` | Four POST requests with the filter and endpoints visible |
| `02-login-outcome.png` | Follow TCP Stream view showing the successful demo login |
| `03-archive-response.png` | Archive request and response, with the response status and MIME type visible |
| `04-export-verification.png` | Your terminal showing matching hashes and the ZIP member |
| `05-payroll-404.png` | The payroll request with its 404 response |

Create a `screenshots/` directory when you have your images and link them from your report. State which capture each screenshot came from.

## Interview practice

- Walk me from the alert to the exact packets that support your conclusion.
- How did you distinguish a file request from bytes actually transmitted?
- What would you need to prove that the authenticated session made the archive request?
- How would TLS change what you could observe, and which server-side logs would you consult?
