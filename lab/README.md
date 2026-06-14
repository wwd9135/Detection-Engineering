# Lab

Home-lab notes and configuration used for rule validation. All hostnames, IP addresses, and domain names are synthetic — this lab runs on personal equipment and contains no employer or production data.

See [docs/lab-architecture.md](../docs/lab-architecture.md) for the full architecture write-up, including the host inventory, telemetry stack, and Sysmon configuration notes.

---

## Quick Reference

| Item | Value |
|---|---|
| Lab domain | `lab.local` (synthetic, non-registered) |
| Subnet | `192.168.100.0/24` (RFC 1918, home lab only) |
| Primary victim host | `LAB-WIN11-01` — Windows 11 22H2 |
| Domain controller | `LAB-WIN2022-DC` — Windows Server 2022 |
| SIEM | Microsoft Sentinel (lab Log Analytics workspace) |
| EDR | Microsoft Defender for Endpoint (MDE) |
| Sysmon | Version 15.14, SwiftOnSecurity config baseline |
| Emulation framework | Atomic Red Team + Invoke-AtomicRedTeam |

---

## Lab Safety Rules

1. The lab VM subnet is isolated from the internet via a NAT gateway — lab hosts cannot initiate outbound connections to external IPs except through an explicit allow-list (Windows Update, MDE cloud, AMA).
2. Snapshots are taken before every emulation test and restored after.
3. Lab hosts are not joined to any real Active Directory domain that connects to employer infrastructure.
4. Log exports committed to this repo are sanitised — real timestamps replaced, real usernames replaced with `LabUser`.

---

## Telemetry Latency Notes

Based on observation in the lab:

| Data source | Typical latency to Sentinel |
|---|---|
| Sysmon via AMA | 2–6 minutes |
| MDE DeviceRegistryEvents | 1–3 minutes |
| MDE DeviceProcessEvents | 1–3 minutes |
| Windows Security events via AMA | 3–8 minutes |

Allow at least 5–10 minutes after an emulation before querying Sentinel to ensure events have ingested.
