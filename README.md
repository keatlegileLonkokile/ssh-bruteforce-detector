# SSH Brute-Force & Account Compromise Detector

A Python tool that plays out a classic SOC (Security Operations Center) analyst task: given a server's SSH authentication log, find the attacks hiding in the noise, tell them apart from normal employee logins, and flag anything that looks like it actually succeeded.

## Scenario

You're a junior analyst at a small company. `webserver01` is a Linux box reachable over SSH, and its `auth.log` from the past week just landed in your queue. Somewhere in ~200 log lines are a handful of employees logging in normally, a couple of scanners/bots hammering the server with password guesses, and — if you're not careful — a successful break-in that looks almost identical to everything else unless you know what to look for.

The goal: build a repeatable tool (not a one-off manual read-through) that parses the log, flags the source IPs behaving like brute-force attacks, flags any IP whose failed attempts were immediately followed by a successful login (a likely compromise), and produces a report a manager or incident responder could actually act on.

## Approach

1. **Parse** each `sshd` log line with a regex, extracting timestamp, event type (`failed` / `accepted`), username, and source IP.
2. **Brute-force detection**: for each IP, slide a time window across its failed attempts. If any 10-minute window contains 5+ failures, flag the IP as `HIGH - BRUTE FORCE`.
3. **Compromise detection**: for each IP, check whether a successful login occurred within 5 minutes of 3+ recent failures from that same IP. If so, flag it `CRITICAL - LIKELY COMPROMISE` — this is the pattern of an attacker guessing their way in and then getting a hit.
4. **Report**: write the flagged IPs to CSV, a plain-English summary with recommendations, and two charts (failed attempts by IP, and a login timeline) for a quick visual read.

## Project structure

```
ssh-bruteforce-detector/
├── data/
│   └── auth.log                  # synthetic sample log (see below)
├── scripts/
│   ├── generate_sample_log.py    # builds the synthetic auth.log
│   └── detect.py                 # the detector itself
├── output/
│   ├── flagged_ips.csv
│   ├── summary.txt
│   ├── failed_logins_by_ip.png
│   └── timeline.png
├── requirements.txt
└── README.md
```

## Setup & usage

```bash
git clone <your-repo-url>
cd ssh-bruteforce-detector
pip install -r requirements.txt

# (optional) regenerate the synthetic sample log
python3 scripts/generate_sample_log.py

# run the detector
python3 scripts/detect.py --log data/auth.log --outdir output
```

To run it against a real log instead, point `--log` at your own `/var/log/auth.log` (format must match standard OpenSSH syslog output).

## About the sample data

`data/auth.log` is **synthetically generated** (see `scripts/generate_sample_log.py`) — no real hosts, users, or attacker IPs. It simulates a week of activity with three layers deliberately mixed together:

- Normal logins from 3 "employee" IPs, occasionally with a mistyped password before success (realistic noise)
- A slow, distributed guessing campaign from two IPs spread across several days (a handful of attempts per hour)
- A fast 45-attempt brute-force burst from one IP in under 3 minutes
- A simulated compromise: 20 failed `root` logins in ~1 minute, immediately followed by a successful login

## Findings (from the sample log)

```
Total login events analyzed : 197
  Failed attempts           : 162
  Successful logins         : 35
Unique source IPs           : 7

CRITICAL ALERTS - 1 likely compromised account:
  - 198.51.100.77 -> successful login as 'root' after 20 failed attempts in ~1 minute

HIGH - 2 IPs flagged for brute-force behavior:
  - 103.42.88.201: 45 failed attempts in under 4 minutes
  - 198.51.100.77: 20 failed attempts (also the source of the compromise above)
```

**Recommendations given to "the client":**

1. Block/rate-limit the flagged IPs at the firewall or via fail2ban.
2. Force an immediate password reset on the `root` account and review its recent activity for further signs of compromise.
3. Move from password auth to SSH key-based auth.
4. Deploy fail2ban (or equivalent) so this kind of blocking happens automatically going forward.
5. Put SSH behind a bastion host / VPN with IP allow-listing instead of exposing it directly to the internet.

## A limitation worth knowing (and why it's here on purpose)

Two IPs in the sample data (`185.220.101.13` and `45.155.204.9`) generated **44-51 failed attempts each** — more than the fast burst that *did* get flagged — but the detector doesn't flag them. Why: their attempts are spread out over multiple days, a handful per hour, so no single 10-minute window ever crosses the 5-failure threshold. That's a real evasion technique ("low and slow" brute-forcing) and a genuine limitation of pure sliding-window detection.

I left this in deliberately rather than tuning it away, because it's a good discussion point: a production version of this tool would add a second detection layer (e.g., total failed attempts per IP over 24-72 hours, or unique-username-per-IP counts to catch username enumeration) rather than relying on one threshold. That's the natural "v2" of this project.

## Possible extensions

- Add a long-window / low-and-slow detector alongside the fast burst detector.
- IP reputation lookup (AbuseIPDB / GreyNoise API) to enrich flagged IPs.
- Geo-IP lookup and a map of attack origins.
- Turn `detect.py` into a small Flask/Streamlit dashboard instead of static CSV/PNG output.
- Ingest real logs on a schedule and alert via Slack/email when a CRITICAL event is found.

## Disclaimer

All data in this repository is synthetically generated for educational/portfolio purposes. No real systems, users, or attackers are represented.
