"""
detect.py

SSH Brute-Force & Account Compromise Detector
-----------------------------------------------
Parses a Linux `auth.log`-style SSH log and flags suspicious activity:

  1. BRUTE-FORCE     - an IP with >= FAILED_THRESHOLD failed logins
                        within a WINDOW_MINUTES sliding window
  2. LIKELY COMPROMISE - an IP that racked up failed attempts and THEN
                        got a successful login within COMPROMISE_WINDOW_MINUTES
                        of its last failure (classic brute-force -> breach pattern)

Usage:
    python3 detect.py --log ../data/auth.log --outdir ../output

Outputs:
    output/flagged_ips.csv   - one row per flagged IP with severity + evidence
    output/summary.txt       - human-readable SOC-style summary
    output/failed_logins_by_ip.png - bar chart of failed attempts per IP
    output/timeline.png      - timeline of failed vs. successful logins
"""

import argparse
import csv
import re
from collections import defaultdict
from datetime import datetime

FAILED_THRESHOLD = 5          # failed attempts to trigger brute-force flag
WINDOW_MINUTES = 10           # sliding window for counting failed attempts
COMPROMISE_WINDOW_MINUTES = 5  # success must occur within this long after a failure burst

LOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.+)$"
)

FAILED_PATTERN = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)
ACCEPTED_PATTERN = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)

YEAR = 2026  # log lines don't include a year; assume current year for this exercise


def parse_log(path):
    events = []  # list of dicts: {ts, type, user, ip}
    with open(path) as f:
        for raw_line in f:
            line = raw_line.strip()
            m = LOG_PATTERN.match(line)
            if not m:
                continue
            ts_str = f"{YEAR} {m.group('month')} {m.group('day')} {m.group('time')}"
            ts = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
            message = m.group("message")

            fm = FAILED_PATTERN.search(message)
            am = ACCEPTED_PATTERN.search(message)
            if fm:
                events.append({"ts": ts, "type": "failed", "user": fm.group("user"), "ip": fm.group("ip")})
            elif am:
                events.append({"ts": ts, "type": "accepted", "user": am.group("user"), "ip": am.group("ip")})
    events.sort(key=lambda e: e["ts"])
    return events


def detect_bruteforce(events):
    """Return dict: ip -> list of failed-attempt timestamps that were part of
    a window where failures crossed FAILED_THRESHOLD."""
    by_ip = defaultdict(list)
    for e in events:
        if e["type"] == "failed":
            by_ip[e["ip"]].append(e["ts"])

    flagged = {}
    for ip, timestamps in by_ip.items():
        timestamps.sort()
        max_in_window = 0
        window_start_for_max = None
        for i, ts in enumerate(timestamps):
            window = [t for t in timestamps if 0 <= (ts - t).total_seconds() <= WINDOW_MINUTES * 60 and t <= ts]
            if len(window) > max_in_window:
                max_in_window = len(window)
                window_start_for_max = window[0]
        if max_in_window >= FAILED_THRESHOLD:
            flagged[ip] = {
                "total_failed": len(timestamps),
                "max_failed_in_window": max_in_window,
                "first_seen": min(timestamps),
                "last_seen": max(timestamps),
            }
    return flagged


def detect_compromise(events, bruteforce_ips):
    """Flag IPs that had a failed-login burst followed shortly by a success."""
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    compromised = {}
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e["ts"])
        failures = [e for e in ip_events if e["type"] == "failed"]
        successes = [e for e in ip_events if e["type"] == "accepted"]
        if not failures or not successes:
            continue
        for s in successes:
            recent_failures = [
                f for f in failures
                if 0 <= (s["ts"] - f["ts"]).total_seconds() <= COMPROMISE_WINDOW_MINUTES * 60
            ]
            if len(recent_failures) >= 3:  # at least a few failures right before the success
                compromised[ip] = {
                    "user": s["user"],
                    "success_time": s["ts"],
                    "preceding_failures": len(recent_failures),
                    "first_failure": min(f["ts"] for f in recent_failures),
                }
                break
    return compromised


def write_csv(bruteforce, compromised, outpath):
    all_ips = set(bruteforce) | set(compromised)
    with open(outpath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "severity", "total_failed_attempts", "max_failed_in_window",
                          "first_seen", "last_seen", "compromised_user", "success_time"])
        for ip in sorted(all_ips):
            severity = "CRITICAL - LIKELY COMPROMISE" if ip in compromised else "HIGH - BRUTE FORCE"
            bf = bruteforce.get(ip, {})
            comp = compromised.get(ip, {})
            writer.writerow([
                ip,
                severity,
                bf.get("total_failed", ""),
                bf.get("max_failed_in_window", ""),
                bf.get("first_seen", ""),
                bf.get("last_seen", ""),
                comp.get("user", ""),
                comp.get("success_time", ""),
            ])


def write_summary(events, bruteforce, compromised, outpath):
    total_failed = sum(1 for e in events if e["type"] == "failed")
    total_accepted = sum(1 for e in events if e["type"] == "accepted")
    unique_ips = len(set(e["ip"] for e in events))

    lines = []
    lines.append("=" * 60)
    lines.append("SSH AUTH LOG - SECURITY ANALYSIS SUMMARY")
    lines.append("=" * 60)
    lines.append(f"Total login events analyzed : {len(events)}")
    lines.append(f"  Failed attempts           : {total_failed}")
    lines.append(f"  Successful logins         : {total_accepted}")
    lines.append(f"Unique source IPs           : {unique_ips}")
    lines.append("")
    lines.append(f"Detection thresholds: >= {FAILED_THRESHOLD} failed logins within "
                  f"{WINDOW_MINUTES} minutes = brute-force flag")
    lines.append("")

    if compromised:
        lines.append(f"CRITICAL ALERTS - {len(compromised)} likely compromised account(s):")
        for ip, c in compromised.items():
            lines.append(
                f"  - {ip} -> successful login as '{c['user']}' at {c['success_time']} "
                f"after {c['preceding_failures']} failed attempts starting {c['first_failure']}"
            )
        lines.append("")
    else:
        lines.append("No successful logins followed a brute-force burst.")
        lines.append("")

    if bruteforce:
        lines.append(f"HIGH - {len(bruteforce)} IP(s) flagged for brute-force behavior:")
        for ip, b in sorted(bruteforce.items(), key=lambda x: -x[1]["max_failed_in_window"]):
            note = " [ALSO LED TO COMPROMISE]" if ip in compromised else ""
            lines.append(
                f"  - {ip}: {b['total_failed']} total failed attempts "
                f"(peak {b['max_failed_in_window']} within {WINDOW_MINUTES} min), "
                f"active {b['first_seen']} to {b['last_seen']}{note}"
            )
    else:
        lines.append("No IPs crossed the brute-force threshold.")

    lines.append("")
    lines.append("RECOMMENDATIONS")
    lines.append("-" * 60)
    lines.append("1. Block/rate-limit the flagged IPs at the firewall or fail2ban.")
    lines.append("2. Force a password reset and review activity for any compromised accounts.")
    lines.append("3. Disable password auth for SSH in favor of key-based authentication.")
    lines.append("4. Enable and monitor fail2ban (or equivalent) to auto-block repeated failures.")
    lines.append("5. Restrict SSH exposure with a bastion host / VPN and IP allow-listing.")

    with open(outpath, "w") as f:
        f.write("\n".join(lines) + "\n")

    print("\n".join(lines))


def make_charts(events, bruteforce, outdir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # Chart 1: failed attempts per IP (top offenders)
    by_ip_failed = defaultdict(int)
    for e in events:
        if e["type"] == "failed":
            by_ip_failed[e["ip"]] += 1
    sorted_ips = sorted(by_ip_failed.items(), key=lambda x: -x[1])[:10]
    ips = [x[0] for x in sorted_ips]
    counts = [x[1] for x in sorted_ips]
    colors = ["#d62728" if ip in bruteforce else "#1f77b4" for ip in ips]

    plt.figure(figsize=(9, 5))
    plt.bar(ips, counts, color=colors)
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Failed login attempts")
    plt.title("Failed SSH Login Attempts by Source IP (red = flagged brute-force)")
    plt.tight_layout()
    plt.savefig(f"{outdir}/failed_logins_by_ip.png", dpi=150)
    plt.close()

    # Chart 2: timeline of failed vs accepted events
    failed_ts = [e["ts"] for e in events if e["type"] == "failed"]
    accepted_ts = [e["ts"] for e in events if e["type"] == "accepted"]

    plt.figure(figsize=(10, 4))
    plt.scatter(failed_ts, [1] * len(failed_ts), color="#d62728", label="Failed", marker="|", s=200)
    plt.scatter(accepted_ts, [1] * len(accepted_ts), color="#2ca02c", label="Accepted", marker="|", s=200)
    plt.yticks([])
    plt.xlabel("Time")
    plt.title("Login Attempt Timeline (failed vs. successful)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{outdir}/timeline.png", dpi=150)
    plt.close()


def main():
    parser = argparse.ArgumentParser(description="Detect SSH brute-force attacks and likely compromises.")
    parser.add_argument("--log", default="data/auth.log", help="Path to the auth.log file")
    parser.add_argument("--outdir", default="output", help="Directory to write results to")
    args = parser.parse_args()

    events = parse_log(args.log)
    bruteforce = detect_bruteforce(events)
    compromised = detect_compromise(events, bruteforce)

    write_csv(bruteforce, compromised, f"{args.outdir}/flagged_ips.csv")
    write_summary(events, bruteforce, compromised, f"{args.outdir}/summary.txt")
    make_charts(events, bruteforce, args.outdir)

    print(f"\nResults written to {args.outdir}/ (flagged_ips.csv, summary.txt, failed_logins_by_ip.png, timeline.png)")


if __name__ == "__main__":
    main()
