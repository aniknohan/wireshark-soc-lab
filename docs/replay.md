# Reproduce the case on an Ubuntu VM

Run this inside Ubuntu. Both endpoints bind to or connect to `127.0.0.1` over the loopback interface. The traffic uses mock responses and a ZIP containing one harmless text file. Your local capture will use loopback IPs, OS-generated TCP metadata, and its own frame numbers.

## 1. Install the tools

```bash
sudo apt update
sudo apt install wireshark tcpdump unzip
```

If asked whether unprivileged users should capture packets, choose **No** for this workflow. Capture with tcpdump and open the saved file in Wireshark as your regular user.

## 2. Start capture in Terminal A

Open a terminal in the extracted repository directory and run:

```bash
sudo tcpdump -i lo -nn -s 0 -U -w /tmp/wireshark-soc-replay.pcap 'tcp port 8080'
```

Wait for `listening on lo`. The capture filter records TCP packets with source or destination port 8080. `-s 0` captures full packets so the archive body can be recovered.

## 3. Generate traffic in Terminal B

Open a second terminal in the same repo directory:

```bash
python3 scripts/lab.py replay
```

Expect seven request/response lines with statuses `200, 401, 401, 401, 200, 200, 404`. The script starts the loopback listener, opens a fresh TCP connection for each request, checks every response, then exits.

## 4. Save your capture and analyze it

Stop tcpdump with **Ctrl+C** in Terminal A and copy the capture into your repository as your user:

```bash
sudo cat /tmp/wireshark-soc-replay.pcap > captures/replay.pcap
wireshark captures/replay.pcap
```

Apply the walkthrough filters. Use TCP ports to tell the two endpoints apart on loopback. Each connection uses an ephemeral client port and server port 8080. Record the frame numbers you actually see and export the inventory ZIP to verify its hash against the reference. If you see apparent checksum errors on locally captured packets, compare the HTTP outcomes and document the capture conditions before treating checksum annotations as evidence.

If tcpdump reports zero packets, check that you started capture before running the script and that both terminals are in the same VM. If Python reports the address is in use, identify the listener with `ss -ltnp 'sport = :8080'` and retry when the port is available. If you are waiting for a previous replay connection to clear, retry after a minute.

## 5. Publish your work

Create an empty GitHub repo named `wireshark-soc-lab`. In the extracted project folder, add your own screenshots and a replay report with your observations, then run:

```bash
git init -b main
git add README.md docs scripts captures evidence .gitignore
git add screenshots
git commit -m "Document simulated Wireshark SOC investigation"
git remote add origin https://github.com/YOUR-USERNAME/wireshark-soc-lab.git
git push -u origin main
```

Run `git add screenshots` once your screenshot directory exists. Review `git status` and publish only lab-generated evidence. The included ignore rule keeps the replay capture local by default. To include a reviewed replay capture, run `git add -f captures/replay.pcap` before committing.

**Resume bullet after completing your replay** — Reproduced and investigated a simulated HTTP login anomaly in Ubuntu using Wireshark, reconstructed seven TCP conversations, verified a transferred archive with SHA-256, and documented the evidence and escalation criteria.
