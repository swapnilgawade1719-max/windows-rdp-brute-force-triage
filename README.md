# Windows RDP Brute-Force Triage

A self-directed SOC analyst home-lab exercise: triaging Windows Security Event Logs with PowerShell to investigate a Remote Desktop (RDP) brute-force intrusion.

> **Note:** This is a hands-on training lab built on simulated event data — not a real production incident.

---

## Scenario

A Windows server (`WIN-SRV01`) with RDP exposed on port 3389 is targeted by an external attacker. Working from exported Windows Security events, the goal is to reconstruct the attack, confirm whether it succeeded, and separate malicious activity from legitimate admin behavior.

## Skills & tools demonstrated

- Windows Security Event Log triage (Event IDs 4625, 4624, 4672, 4720, 4732, 1102)
- Interpreting **Logon Types** (Type 10 = RDP) and **status codes** (`0xC000006A` vs `0xC0000064`)
- PowerShell analysis: `Import-Csv`, `Where-Object`, `Group-Object`, `Sort-Object`
- Distinguishing a **malicious privileged logon from a legitimate one** (source IP, host, and time context)
- Identifying persistence and log-clearing anti-forensics
- Incident reporting with IOCs, impact assessment, and MITRE ATT&CK mapping

## Key findings

- **46 failed RDP logons in ~90 seconds** from a single external IP (`45.134.26.13`), all Logon Type 10.
- Status-code analysis showed the attacker moved from **guessing usernames** to **guessing the password of the valid `Administrator` account** — which then **succeeded** (Event 4624).
- Post-compromise: a **backdoor admin account (`helpdesk_svc`)** was created and the **Security event log was cleared** (Event 1102).
- A separate privileged logon was **validated as legitimate** (internal IP, business hours) and correctly excluded from the incident.

## MITRE ATT&CK

`T1110.001` Password Guessing · `T1021.001` RDP · `T1136.001` Create Account · `T1070.001` Clear Windows Event Logs

---

## Repository contents

| File | Description |
|------|-------------|
| [`INCIDENT_REPORT.md`](INCIDENT_REPORT_Lab2.md) | Full incident report — timeline, IOCs, impact, recommendations |
| `windows_security.csv` | The Windows Security event dataset analyzed |

**➡️ Read the full investigation in [INCIDENT_REPORT.md](INCIDENT_REPORT_Lab2.md).**
