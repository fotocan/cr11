# Incident Report

Complete this as you work, not at the end. Recording findings while they are
in front of you is the habit that separates a usable report from a
reconstruction.

**Analyst:**
**Date:**
**Incident reference:**

---

## 1. Summary

Two or three sentences. What happened, to which systems, and what the
attacker was attempting to achieve. Written so a manager who reads nothing
else understands the incident.

---

## 2. Affected systems

| Host | Role | How it was involved |
|---|---|---|
| | | |

---

## 3. Compromised accounts

| Account | Type | How it was compromised | Evidence |
|---|---|---|---|
| | | | |

---

## 4. Timeline

Use `timeline.csv` for the working version, then summarise the significant
events here.

| Time (UTC) | Host | Event | Source |
|---|---|---|---|
| | | | |

---

## 5. Indicators of compromise

| Type | Value | Where observed |
|---|---|---|
| IP address | | |
| Domain | | |
| File path | | |
| File hash | | |
| Registry key | | |
| Scheduled task | | |

---

## 6. Techniques observed

Map each stage to MITRE ATT&CK. State the evidence, not just the ID.

| Technique | ID | Evidence |
|---|---|---|
| | | |

---

## 7. Containment and eradication

| Action | System | Justification | Operational impact | Verified by |
|---|---|---|---|---|
| | | | | |

The operational impact column matters. Disabling an account stops the
attacker and stops whatever legitimately depended on that account. State
what you weighed.

---

## 8. Recommendations

What would have prevented this, or detected it sooner? Consider both the
technical controls and the conditions that let the initial access succeed.

---

## 9. Outstanding questions

What could you not establish from the available evidence, and what would you
need in order to answer it?
