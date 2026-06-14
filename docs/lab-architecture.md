# Home Lab Architecture

All detections in this portfolio were validated in a personal home lab running on hardware I own. No production systems, employer infrastructure, or real user data are involved.

---

## Purpose

The lab exists to:
1. **Generate synthetic telemetry** — run attack emulations and capture the resulting log events.
2. **Validate that rules fire** — confirm Sigma-compiled KQL returns expected results against the generated telemetry.
3. **Tune against FP baselines** — observe rule behaviour across normal system activity to identify noise.

---

## High-Level Topology

```
┌─────────────────────────────────────────────────────────────────┐
│  Home Lab (192.168.100.0/24 — synthetic, non-routable range)    │
│                                                                 │
│  ┌──────────────────┐    ┌──────────────────┐                  │
│  │  LAB-WIN11-01    │    │  LAB-WIN2022-DC  │                  │
│  │  Windows 11 22H2 │    │  Windows Server  │                  │
│  │  (victim host)   │    │  2022 (AD DC)    │                  │
│  │                  │    │                  │                  │
│  │  • Sysmon 15.x   │    │  • Sysmon 15.x   │                  │
│  │  • MDE onboarded │    │  • MDE onboarded │                  │
│  │  • AMA agent     │    │  • AMA agent     │                  │
│  └────────┬─────────┘    └────────┬─────────┘                  │
│           │                       │                             │
│           └───────────┬───────────┘                             │
│                       │                                         │
│             ┌─────────▼──────────┐                              │
│             │  Azure Monitor /   │                              │
│             │  Log Analytics     │                              │
│             │  Workspace         │                              │
│             │  (Microsoft        │                              │
│             │   Sentinel)        │                              │
│             └────────────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
```

> **Note**: IP addresses shown above are from RFC 1918 private ranges used only within the lab. No public IPs or real hostnames appear in this documentation or any log excerpts.

---

## Hosts

| Hostname | OS | Role | Key Software |
|---|---|---|---|
| `LAB-WIN11-01` | Windows 11 22H2 | Victim workstation — emulation target | Sysmon 15.x, MDE sensor, AMA agent |
| `LAB-WIN2022-DC` | Windows Server 2022 | Active Directory Domain Controller | Sysmon 15.x, MDE sensor, AMA agent, AD DS |

Hostnames are synthetic and follow the pattern `LAB-{OS}-{NN}` to make it clear these are lab machines.

---

## Telemetry Stack

| Layer | Product | Tables in Sentinel |
|---|---|---|
| Endpoint process / file / registry | Sysmon 15.x → AMA → Sentinel | `SecurityEvent`, `SysmonEvent` (via Custom Logs) |
| Endpoint EDR events | Microsoft Defender for Endpoint | `DeviceProcessEvents`, `DeviceRegistryEvents`, `DeviceFileEvents`, `DeviceNetworkEvents` |
| Windows Security event log | AMA → Sentinel | `SecurityEvent` |
| DNS (stub) | Corelight sensor (future) | `CiscoUmbrellaLog` / `DnsEvents` |

---

## Sysmon Configuration

The lab runs a Sysmon configuration derived from the [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) baseline, with the following categories explicitly enabled:

- Event ID 1 — Process Create
- Event ID 3 — Network Connection
- Event ID 7 — Image Load (DLL)
- Event ID 10 — Process Access (LSASS)
- Event ID 11 — File Create
- Event ID 12/13/14 — Registry Create/Set/Delete
- Event ID 22 — DNS Query

The full config is not committed here (it would reveal host-specific details) but the version in use is noted in each `validation.md` where relevant.

---

## Emulation Tooling

| Tool | Purpose |
|---|---|
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Technique-level emulations mapped to ATT&CK |
| PowerShell (manual) | Ad-hoc emulations where no ART test exists |
| [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) | PowerShell runner for ART tests |

Emulation procedures and test IDs are documented in [emulation/](../emulation/).

---

## Data Handling

- Log exports used as evidence in `validation.md` files are **manually sanitised** before committing — real timestamps and process IDs are replaced with synthetic equivalents.
- No screenshots containing real usernames, domain names, internal IPs, or employer-identifiable strings are committed.
- The lab domain is `lab.local` — a non-routable, non-registered name used only within the lab network.

---

## Limitations

- The lab is a single-user, low-activity environment. FP rates observed here will differ from a real enterprise with hundreds of active users and diverse software installations.
- Not all data sources are available (e.g., no Corelight NDR yet — network detections are theoretical until hardware is added).
- Resource constraints mean some detections can only be validated conceptually against technique documentation rather than live emulation.
