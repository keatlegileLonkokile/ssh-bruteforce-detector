"""
generate_sample_log.py

Creates a synthetic Linux SSH auth.log for the SSH Brute-Force Detector
portfolio project. The log simulates one week of activity on a small
Ubuntu server with:

  - Normal, legitimate logins from a handful of known employee IPs
  - A slow/distributed brute-force campaign from a few attacker IPs
  - One "smash and grab" fast brute-force burst
  - A successful login on the victim account AFTER a burst of failures
    (i.e. a simulated successful compromise) so the detector has a
    true positive "high severity" event to catch

This is synthetic data generated for demonstration purposes only.
No real hosts, users, or IP addresses are represented.
"""

import random
from datetime import datetime, timedelta

random.seed(42)

USERS = ["root", "admin", "deploy", "ubuntu", "backup", "jsmith", "kmokoena"]
LEGIT_USERS = ["jsmith", "kmokoena", "deploy"]

LEGIT_IPS = ["10.0.0.15", "10.0.0.22", "10.0.0.31"]
ATTACKER_IPS = ["185.220.101.13", "45.155.204.9", "103.42.88.201"]
COMPROMISE_IP = "198.51.100.77"

SSH_PORT_POOL = list(range(40000, 60000))

start_time = datetime(2026, 8, 3, 0, 0, 0)  # one week before "today"
lines = []


def log_line(ts, event, user, ip, port):
    if event == "failed":
        msg = f"Failed password for {user} from {ip} port {port} ssh2"
    elif event == "invalid":
        msg = f"Failed password for invalid user {user} from {ip} port {port} ssh2"
    elif event == "accepted":
        msg = f"Accepted password for {user} from {ip} port {port} ssh2"
    elif event == "closed":
        msg = f"Connection closed by {ip} port {port} [preauth]"
    ts_str = ts.strftime("%b %d %H:%M:%S")
    # pad day like real syslog (e.g. "Aug  3")
    ts_str = ts_str.replace(
        ts.strftime("%b "), ts.strftime("%b ").ljust(4) if ts.day >= 10 else ts.strftime("%b") + "  "
    )
    return f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')} webserver01 sshd[{random.randint(1000,9999)}]: {msg}"


# 1. Normal daily logins from legit IPs across the week
t = start_time
for day in range(7):
    for _ in range(random.randint(3, 6)):
        ts = start_time + timedelta(days=day, hours=random.randint(7, 19), minutes=random.randint(0, 59))
        ip = random.choice(LEGIT_IPS)
        user = random.choice(LEGIT_USERS)
        port = random.choice(SSH_PORT_POOL)
        # occasional legit typo before success
        if random.random() < 0.15:
            lines.append((ts, log_line(ts, "failed", user, ip, port)))
            ts2 = ts + timedelta(seconds=random.randint(2, 8))
            lines.append((ts2, log_line(ts2, "accepted", user, ip, port)))
        else:
            lines.append((ts, log_line(ts, "accepted", user, ip, port)))

# 2. Slow/distributed brute-force from attacker IPs across several days
#    (a handful of attempts per hour, spread out to try to fly under the radar)
for ip in ATTACKER_IPS[:2]:
    for day in range(2, 6):
        for _ in range(random.randint(8, 14)):
            ts = start_time + timedelta(
                days=day, hours=random.randint(0, 23), minutes=random.randint(0, 59), seconds=random.randint(0, 59)
            )
            user = random.choice(USERS)
            port = random.choice(SSH_PORT_POOL)
            lines.append((ts, log_line(ts, "invalid" if user not in LEGIT_USERS else "failed", user, ip, port)))

# 3. Fast "smash and grab" brute-force burst - many attempts in a few minutes
burst_ip = ATTACKER_IPS[2]
burst_start = start_time + timedelta(days=4, hours=3, minutes=12)
for i in range(45):
    ts = burst_start + timedelta(seconds=i * random.randint(2, 5))
    user = random.choice(USERS)
    port = random.choice(SSH_PORT_POOL)
    lines.append((ts, log_line(ts, "invalid" if user not in LEGIT_USERS else "failed", user, ip=burst_ip, port=port)))

# 4. Simulated COMPROMISE: burst of failures against "root" then a success
compromise_start = start_time + timedelta(days=5, hours=2, minutes=41)
for i in range(20):
    ts = compromise_start + timedelta(seconds=i * 3)
    port = random.choice(SSH_PORT_POOL)
    lines.append((ts, log_line(ts, "failed", "root", COMPROMISE_IP, port)))
success_ts = compromise_start + timedelta(seconds=20 * 3 + 4)
port = random.choice(SSH_PORT_POOL)
lines.append((success_ts, log_line(success_ts, "accepted", "root", COMPROMISE_IP, port)))

# Sort all lines chronologically like a real log file
lines.sort(key=lambda x: x[0])

with open("data/auth.log", "w") as f:
    for _, line in lines:
        f.write(line + "\n")

print(f"Generated {len(lines)} log lines -> data/auth.log")
