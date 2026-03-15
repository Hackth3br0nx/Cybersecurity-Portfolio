# 04 — SIEM / Threat Hunting Project

**Analyst:** Alejandro Garcia (CyberJudoSec)  
**Tools:** Microsoft Sentinel · Splunk · KQL · Defender for Identity  
**Skills:** Threat Hunting · Detection Engineering · Log Analysis · Incident Response · MITRE ATT&CK  
**Difficulty:** Advanced  

---

## Scenario

Enterprise authentication logs and endpoint telemetry showed unusual patterns across several hosts. No formal alert had fired — this was an observation-driven hunt initiated after a routine log review flagged statistical anomalies in sign-in behavior. The hypothesis: a threat actor was using compromised credentials to access resources from geographically inconsistent locations.

---

## Objective

- Hunt for evidence of credential compromise using authentication telemetry
- Identify impossible travel login patterns using KQL in Microsoft Sentinel
- Correlate findings with endpoint telemetry in Splunk
- Map observed behavior to MITRE ATT&CK
- Document timeline and produce incident report

---

## Tools Used

| Tool | Purpose |
|---|---|
| Microsoft Sentinel | Primary SIEM — KQL hunting |
| Splunk | Endpoint telemetry correlation |
| Defender for Identity | Identity threat signals |
| MITRE ATT&CK Navigator | TTP mapping |
| KQL | Detection query development |
| Splunk SPL | Log correlation queries |

---

## Hypothesis

> A threat actor is using compromised credentials to authenticate from locations physically impossible to travel between in the observed timeframe — indicating stolen credentials being used remotely.

---

## Hunt Steps

### 1. Establish Baseline — Normal Sign-in Behavior
```kql
SigninLogs
| where TimeGenerated > ago(30d)
| summarize LoginCount=count(), Locations=dcount(Location) by UserPrincipalName
| where Locations > 1
| order by Locations desc
```

### 2. Impossible Travel Detection Query
```kql
let timedelta = 2h;
SigninLogs
| where ResultType == 0
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize 
    Logins=count(),
    Locations=make_set(strcat(City, ", ", Country)),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated)
    by UserPrincipalName, bin(TimeGenerated, timedelta)
| where array_length(Locations) > 1
| extend TimeDiff = datetime_diff('minute', LastSeen, FirstSeen)
| where TimeDiff < 120
| project UserPrincipalName, Locations, TimeDiff, FirstSeen, LastSeen
| order by TimeDiff asc
```

**Result:** 3 accounts flagged with sign-ins from 2+ countries within 30-minute windows.

### 3. Endpoint Correlation in Splunk
```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=4624
| eval Account=mvindex(split(Account_Name, "@"),0)
| stats count by Account, Workstation_Name, Source_Network_Address, _time
| where count > 5
| sort - count
```

**Result:** One account showed lateral movement — authenticated to 4 workstations within 8 minutes.

### 4. MITRE ATT&CK Mapping

| Technique ID | Technique | Evidence |
|---|---|---|
| T1078 | Valid Accounts | Stolen credentials used for authentication |
| T1021.001 | Remote Desktop Protocol | RDP sessions from external IPs |
| T1550.002 | Pass the Hash | Lateral movement without re-authentication prompts |
| T1078.004 | Cloud Accounts | Azure sign-ins from anomalous locations |

### 5. Timeline Reconstruction

| Time | Event |
|---|---|
| 02:14 UTC | First sign-in from US-based IP — normal |
| 02:47 UTC | Sign-in from Eastern European IP — same account |
| 02:49 UTC | Lateral movement to 4 workstations begins |
| 03:02 UTC | Attempted access to file server |
| 03:15 UTC | Account disabled by analyst |

---

## Detection Rules Developed

### KQL — Impossible Travel Alert
```kql
SigninLogs
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| partition by UserPrincipalName (
    order by TimeGenerated asc
    | extend PrevCountry = prev(Country)
    | extend PrevTime = prev(TimeGenerated)
    | extend MinutesDiff = datetime_diff('minute', TimeGenerated, PrevTime)
    | where Country != PrevCountry and MinutesDiff < 120
)
| project TimeGenerated, UserPrincipalName, Country, PrevCountry, MinutesDiff
```

---

## Incident Report Summary

**Incident:** Compromised Credential — Impossible Travel  
**Severity:** High  
**Affected Accounts:** 3 user accounts  
**Affected Hosts:** 4 workstations  
**Attack Vector:** Stolen credentials used from external IP  
**Containment:** Accounts disabled, sessions terminated, passwords reset  
**Recommended Actions:** Enable MFA enforcement, implement conditional access policies, deploy identity protection alerts

---

## What I Learned

- Impossible travel is one of the most reliable credential compromise indicators available in authentication logs
- KQL's `prev()` function is powerful for building sequential event detection logic
- Correlating SIEM alerts with endpoint telemetry dramatically increases confidence in findings
- Mapping findings to MITRE ATT&CK makes them immediately actionable for detection engineering

---

## Files

```
04-siem-threat-hunting/
├── README.md               ← This file
├── detections/             ← KQL and SPL detection queries
├── screenshots/            ← Sentinel and Splunk screenshots
└── incident-report.md      ← Full incident report
```
