# Incident Report: RDP Brute-Force Compromise of `WIN-SRV01`

| Field | Detail |
|---|---|
| **Report ID** | IR-2026-002 |
| **Analyst** | Swapnil |
| **Affected host** | `WIN-SRV01` |
| **Data source** | Windows Security Event Log |
| **Attack vector** | Remote Desktop Protocol (RDP, TCP 3389) |
| **Severity** | **Critical** |
| **Status** | Confirmed incident — compromise successful, persistence established, logs cleared |
| **Classification** | Brute Force → Unauthorized Access → Persistence → Defense Evasion |

---

## 1. Executive Summary

An external attacker at `45.134.26.13` conducted an automated RDP brute-force attack against `WIN-SRV01`. After spraying common usernames, the attacker identified the valid built-in `Administrator` account and guessed its password, achieving a successful logon at **02:15:31** — roughly **90 seconds** after the attack began.

Once inside, the attacker created a privileged backdoor account (`helpdesk_svc`), added it to the local Administrators group, and then **cleared the Windows Security event log** to hinder investigation. The host should be treated as fully compromised.

A separate privileged logon by `jmiller` was reviewed and assessed as **legitimate baseline activity** (internal source, business hours) — see Section 3.6.

---

## 2. Timeline of Events

| Time (2026-11-15) | Event ID | Activity | Significance |
|---|---|---|---|
| 09:12:04 | 4624 / 4672 | `jmiller` interactive logon from `10.10.5.22` (HR-PC-07) | **Baseline** — legitimate |
| 13:40:55 | 4624 | `jmiller` RDP logon from `10.10.5.22` | Baseline — legitimate |
| **02:14:00** | 4625 | Username spray begins from `45.134.26.13` (Type 10 / RDP) | **Attack starts** |
| 02:14:00–02:15:28 | 4625 ×46 | 8 invalid-user + 38 `Administrator` failures | Automated brute force |
| **02:15:31** | 4624 | **Successful RDP logon — `Administrator` from `45.134.26.13`** | **COMPROMISE** |
| 02:15:33 | 4672 | Special privileges assigned to new logon | Admin-level access confirmed |
| 02:15:41 | 4720 | Account created: `helpdesk_svc` | **Persistence** — backdoor |
| 02:15:45 | 4732 | `helpdesk_svc` added to local **Administrators** | Privilege escalation of backdoor |
| 02:15:51 | 4724 | Password set for `helpdesk_svc` | Backdoor finalized |
| 02:16:11 | 1102 | **The audit log was cleared** | **Defense evasion** |

**Attack velocity:** 46 failed logons in ~90 seconds, all Logon Type 10 from a single external IP — the signature of an automated RDP brute-force tool, not human error.

---

## 3. Investigation & Findings

### 3.1 Scale of the attack
```powershell
(Import-Csv .\windows_security.csv | Where-Object EventID -eq '4625').Count
```
**Result: 46 failed logons (Event ID 4625).**

### 3.2 Source of the attack
```powershell
Import-Csv .\windows_security.csv | Where-Object EventID -eq '4625' |
  Group-Object IpAddress | Sort-Object Count -Descending | Select-Object Count, Name
```
**Result: all 46 failures originated from a single external IP, `45.134.26.13`.**

### 3.3 Targeted accounts
```powershell
Import-Csv .\windows_security.csv | Where-Object EventID -eq '4625' |
  Group-Object TargetUserName | Sort-Object Count -Descending | Select-Object Count, Name
```
**Result: 38 attempts against `Administrator`, 8 spread across invalid usernames.** The concentration on `Administrator` shows the attacker located a valid, high-value account.

### 3.4 Failure reason (SubStatus)
```powershell
Import-Csv .\windows_security.csv | Where-Object EventID -eq '4625' |
  Group-Object SubStatus | Select-Object Count, Name
```
**Result:**
- `0xC000006A` (valid username, wrong password) — **38 attempts** against `Administrator`. The attacker knew this account exists and was guessing its password.
- `0xC0000064` (username does not exist) — 8 attempts. The attacker was probing for other valid accounts.

This split is the key insight: the attacker moved from *guessing account names* to *guessing the password of a confirmed real account*.

### 3.5 The pivot — successful logon
```powershell
Import-Csv .\windows_security.csv |
  Where-Object { $_.EventID -eq '4624' -and $_.IpAddress -eq '45.134.26.13' }
```
**Result: a successful logon (4624) for `Administrator` from `45.134.26.13` at 02:15:31, Logon Type 10 (RDP).** The brute force succeeded.

### 3.6 Baseline validation (ruling out a false positive)
A `4672` (special privileges assigned) event was also observed for `jmiller`. This was assessed and determined to be **legitimate**: it originated from the internal IP `10.10.5.22`, workstation `HR-PC-07`, at 09:12 during business hours — consistent with normal administrative activity. It is **not** part of this incident. (Distinguishing malicious privilege use from routine admin activity by source, host, and timing.)

### 3.7 Post-compromise activity
```powershell
Import-Csv .\windows_security.csv |
  Where-Object { '4672','4720','4732','4724','1102' -contains $_.EventID }
```
**Result:** immediately after the successful logon, the attacker (all from `45.134.26.13`):
- **4672** — obtained administrative privileges,
- **4720** — created a new account `helpdesk_svc` (a **backdoor**),
- **4732** — added `helpdesk_svc` to the local **Administrators** group,
- **4724** — set the backdoor's password,
- **1102** — **cleared the Windows Security event log** to impede investigation.

---

## 4. Indicators of Compromise (IOCs)

| Type | Indicator | Action |
|---|---|---|
| Source IP | `45.134.26.13` | Block at firewall / perimeter |
| Affected host | `WIN-SRV01` | Isolate and rebuild |
| Compromised account | `Administrator` | Reset credentials; assume compromised |
| Malicious account | `helpdesk_svc` | Remove immediately |
| Anti-forensics | Security log cleared (Event ID 1102) | Log integrity lost after 02:16:11 |

---

## 5. Impact Assessment

- **Confirmed unauthorized administrative access** to `WIN-SRV01` via the built-in `Administrator` account over RDP.
- **Persistence established** through the backdoor account `helpdesk_svc`, which holds local admin rights and survives a reset of the `Administrator` password.
- **Log integrity compromised** — with the Security log cleared at 02:16:11, any attacker activity after that point may be unlogged; the full scope cannot be assumed from these events alone.
- The host must be treated as **fully compromised** (Confidentiality, Integrity, Availability all at risk).

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Initial Access / Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 |
| Persistence / Privilege Escalation | Valid Accounts: Local Accounts | T1078.003 |
| Persistence | Create Account: Local Account | T1136.001 |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 |

---

## 7. Recommendations

**Immediate containment**
- Block `45.134.26.13` at the perimeter.
- Isolate `WIN-SRV01` from the network.
- Disable/reset the `Administrator` account; remove the `helpdesk_svc` backdoor.
- Preserve any remaining logs and forward to the SIEM before remediation.

**Eradication & recovery**
- Because admin access was achieved and logs were cleared, **rebuild the host from a known-good image**.
- Hunt for `45.134.26.13` and `helpdesk_svc` across the estate to check for lateral movement.

**Hardening (prevent recurrence)**
- Remove direct internet exposure of RDP; require **VPN or an RD Gateway**, and enable **Network Level Authentication (NLA)**.
- Enforce an **account lockout policy** to blunt brute-force attempts.
- Rename/disable the built-in `Administrator` account and enforce **MFA** for remote access.
- Forward Security logs to a **central SIEM** so log-clearing (1102) can't destroy the only copy, and alert on 1102, off-hours 4624 from external IPs, and new-account/group-change events (4720/4732).

---

## 8. Appendix — Methodology

Analysis performed on exported Windows Security events using PowerShell (`Import-Csv`, `Where-Object`, `Group-Object`, `Sort-Object`). On a live host the same hunt uses `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}` or Event Viewer with a filter on the relevant Event IDs.

*Prepared as a hands-on SOC analyst lab exercise (Lab 2 — Windows Log Triage / RDP Brute Force).*
