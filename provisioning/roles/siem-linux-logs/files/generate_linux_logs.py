#!/usr/bin/env python3
"""
Generate LNX01's log set for A2.

LNX01 is the scenario's internal file and backup server. It is not a running
VM — no level investigates Linux, so a whole node would be spent on data
alone. Its logs are written here at provision time and read by the Wazuh
manager, which gives trainees a genuine third telemetry source without the
RAM cost.

Everything below is ordinary operational activity: cron jobs, backup runs,
SSH sessions from the admin subnet, package updates. There is no attacker
activity on LNX01. That is the point of A2 — trainees must recognise which
sources exist and learn to tell routine noise from the incident, rather than
assuming every log file contains something interesting.

The backup service account appears here doing its normal nightly work, which
is what makes svc-backup plausible as a credential target later in the chain.

Timestamps are written relative to build time so this data lands in the same
window as the live artefacts on WS01 and DC01.
"""

import random
import sys
from datetime import datetime, timedelta, timezone

HOST = sys.argv[1] if len(sys.argv) > 1 else "LNX01"
IP = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.20"
OUT = "/opt/cr11"

now = datetime.now(timezone.utc)
start = now - timedelta(hours=8)

ADMINS = ["m.horvat", "a.kovac", "root"]
ADMIN_SUBNET = "10.0.5."
SERVICE_ACCOUNT = "svc-backup"

auth, syslog, audit = [], [], []


def ts(t):
    """Syslog timestamp: 'Aug 10 14:03:22'."""
    return t.strftime("%b %e %H:%M:%S").replace("  ", "  ")


def audit_ts(t):
    return f"{t.timestamp():.3f}:{random.randint(1000, 9999)}"


def add_auth(t, msg):
    auth.append((t, f"{ts(t)} {HOST} {msg}"))


def add_syslog(t, msg):
    syslog.append((t, f"{ts(t)} {HOST} {msg}"))


def add_audit(t, msg):
    audit.append((t, f"type=SYSCALL msg=audit({audit_ts(t)}): {msg}"))


# ----------------------------------------------------------------------
# Cron. Runs constantly on any real server and is most of the volume.
# ----------------------------------------------------------------------
t = start
while t < now:
    add_syslog(t, f"CRON[{random.randint(1000, 9999)}]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)")
    t += timedelta(minutes=10)

# ----------------------------------------------------------------------
# The nightly backup run. svc-backup authenticates over SSH from the backup
# scheduler, mounts the share, and writes its archive. Entirely routine —
# and the reason those credentials exist on the network at all.
# ----------------------------------------------------------------------
backup_start = start + timedelta(hours=1, minutes=12)
pid = random.randint(2000, 9999)
add_auth(backup_start, f"sshd[{pid}]: Accepted publickey for {SERVICE_ACCOUNT} from 10.0.5.40 port 51422 ssh2: RSA SHA256:qL3n8Vx2pR7mYtKcW9fBdA5jHsE1uZgN4oXvC6iTyPk")
add_auth(backup_start, f"sshd[{pid}]: pam_unix(sshd:session): session opened for user {SERVICE_ACCOUNT}(uid=1004) by (uid=0)")
add_syslog(backup_start + timedelta(seconds=3), f"backup-agent[{pid + 1}]: starting nightly archive job id=nightly-{backup_start.strftime('%Y%m%d')}")
add_syslog(backup_start + timedelta(minutes=2), f"backup-agent[{pid + 1}]: archiving /srv/shares/finance (14.2 GB)")
add_syslog(backup_start + timedelta(minutes=19), f"backup-agent[{pid + 1}]: archiving /srv/shares/engineering (31.7 GB)")
add_syslog(backup_start + timedelta(minutes=44), f"backup-agent[{pid + 1}]: archive complete, 45.9 GB written to /mnt/backup/nightly")
add_syslog(backup_start + timedelta(minutes=44, seconds=8), f"backup-agent[{pid + 1}]: job id=nightly-{backup_start.strftime('%Y%m%d')} completed rc=0")
add_auth(backup_start + timedelta(minutes=45), f"sshd[{pid}]: pam_unix(sshd:session): session closed for user {SERVICE_ACCOUNT}")

# ----------------------------------------------------------------------
# Administrator sessions from the admin subnet. Includes sudo, a couple of
# mistyped passwords, and one session that ends without a clean logout —
# all of which is what a normal week looks like.
# ----------------------------------------------------------------------
for i in range(4):
    t = start + timedelta(hours=random.uniform(0.5, 7.5))
    user = random.choice(ADMINS[:2])
    src = ADMIN_SUBNET + str(random.randint(20, 60))
    pid = random.randint(2000, 9999)

    if random.random() < 0.3:
        add_auth(t, f"sshd[{pid}]: Failed password for {user} from {src} port {random.randint(40000, 60000)} ssh2")
        t += timedelta(seconds=random.randint(6, 20))

    add_auth(t, f"sshd[{pid}]: Accepted password for {user} from {src} port {random.randint(40000, 60000)} ssh2")
    add_auth(t, f"sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}(uid={1001 + ADMINS.index(user)}) by (uid=0)")

    for cmd in random.sample([
        "/usr/bin/systemctl status nfs-server",
        "/usr/bin/df -h",
        "/usr/bin/journalctl -u backup-agent --since today",
        "/usr/bin/apt list --upgradable",
        "/usr/bin/tail -n 200 /var/log/syslog",
    ], k=random.randint(1, 3)):
        t += timedelta(seconds=random.randint(20, 400))
        add_auth(t, f"sudo:  {user} : TTY=pts/{random.randint(0, 3)} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}")
        add_audit(t, f'arch=c000003e syscall=59 success=yes exit=0 ppid={pid} pid={pid + 1} auid={1001 + ADMINS.index(user)} uid=0 gid=0 euid=0 comm="{cmd.split("/")[-1].split()[0]}" exe="{cmd.split()[0]}" key="privileged-command"')

    t += timedelta(minutes=random.randint(4, 25))
    add_auth(t, f"sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}")

# ----------------------------------------------------------------------
# Routine service noise: NFS, package updates, log rotation, systemd timers.
# ----------------------------------------------------------------------
noise = [
    "systemd[1]: Started Daily apt download activities.",
    "systemd[1]: logrotate.service: Deactivated successfully.",
    "rpc.mountd[812]: authenticated mount request from 10.0.0.4:718 for /srv/shares/finance",
    "rpc.mountd[812]: authenticated mount request from 10.0.0.5:964 for /srv/shares/engineering",
    "kernel: [UFW BLOCK] IN=ens3 OUT= SRC=10.0.5.19 DST=" + IP + " PROTO=TCP SPT=51234 DPT=23",
    "systemd-timesyncd[701]: Contacted time server 10.0.0.5:123 (dc01.corp.local).",
    "chronyd[744]: Selected source 10.0.0.5",
    "unattended-upgrade: Packages that were upgraded: libssl3 openssl",
    "nfsd[901]: Ignoring lock request from unknown client",
]
for _ in range(60):
    t = start + timedelta(seconds=random.randint(0, 8 * 3600))
    add_syslog(t, random.choice(noise))

# ----------------------------------------------------------------------
# A handful of audit records that are not sudo — file access on the shares,
# which is what an audit rule on a file server would actually capture.
# ----------------------------------------------------------------------
for _ in range(15):
    t = start + timedelta(seconds=random.randint(0, 8 * 3600))
    add_audit(t, f'arch=c000003e syscall=257 success=yes exit=3 auid={random.choice([1001, 1002, 1004])} uid={random.choice([1001, 1002, 1004])} comm="rsync" exe="/usr/bin/rsync" key="share-access"')

# ----------------------------------------------------------------------
# Write everything in time order.
# ----------------------------------------------------------------------
for name, lines in (("auth", auth), ("syslog", syslog), ("audit", audit)):
    # Sort by the recorded time rather than lexically: string sorting puts
    # "Aug  9" before "Aug 10" but breaks down across month boundaries and
    # single-digit days.
    lines.sort(key=lambda x: x[0])
    lines[:] = [x[1] for x in lines]
    path = f"{OUT}/lnx01-{name}.log"
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"{path}: {len(lines)} lines")

print(f"window: {start.strftime('%Y-%m-%d %H:%M')} to {now.strftime('%Y-%m-%d %H:%M')} UTC")
print("content: routine operations only — no attacker activity on LNX01")
