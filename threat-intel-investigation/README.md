# Malicious Infrastructure Investigation · Microsoft Sentinel

**Analyst:** Alejandro Garcia (CyberJudoSec)  
**Tools:** Maltego · Shodan · VirusTotal · Censys · SpiderFoot · Microsoft Sentinel  
**Skills:** OSINT Investigation · Threat Intelligence · IOC Analysis · MITRE ATT&CK Mapping · Intel Report Writing  
**Difficulty:** Intermediate  

---

## Scenario

Suspicious domain and IP addresses appeared in enterprise telemetry with no clear attribution. Multiple endpoints had made outbound connections to the same cluster of external infrastructure over a 72-hour window. The SOC flagged the indicators but could not determine whether they were part of an active attacker campaign, commodity malware noise, or a false positive.

---

## Goal

Identify the full scope of attacker infrastructure, map relationships between indicators, and produce an actionable threat intelligence report for the detection team — including IOCs, infrastructure relationships, and MITRE ATT&CK technique mappings ready for detection rule development.

---

## Tools Used

| Tool | Purpose |
|---|---|
| Maltego | Pivot across domains, IPs, registrants, hosting providers |
| Shodan | Identify open ports, services, and banners on suspect IPs |
| VirusTotal | Cross-reference domains and IPs against threat intelligence feeds |
| Censys | Enumerate SSL certificates and infrastructure relationships |
| SpiderFoot | Automated OSINT enumeration across multiple sources |
| Microsoft Sentinel | Review original telemetry and connection logs |

---

## Actions

### 1. Initial Indicator Review
Pulled the original IOCs from Sentinel connection logs:
- 3 suspicious domains
- 2 external IP addresses
- 1 URL pattern observed in HTTP POST requests

### 2. Maltego Investigation
Loaded all indicators into Maltego. Ran transforms:
- `Domain to IP` — resolved all 3 domains to infrastructure
- `IP to ASN` — identified hosting provider (bulletproof host, known for abuse)
- `Domain to Registrant` — found shared registrant email across 2 of 3 domains
- `IP to Passive DNS` — uncovered 7 additional domains hosted on same IP

**Finding:** 3 seed indicators expanded to 12 related infrastructure nodes sharing hosting, registrant, and SSL certificate patterns.

### 3. Shodan Enrichment
Queried each IP address in Shodan:
- Port 4444 open — common C2 port
- Port 8080 open — HTTP proxy, no reverse DNS
- Banner: `Apache/2.4.41` on non-standard port — consistent with staged C2 infrastructure

### 4. VirusTotal Correlation
Cross-referenced all domains and IPs against VirusTotal:
- 2 of 3 original domains: previously flagged by 6+ threat intel vendors
- 1 domain: clean — likely newly registered infrastructure
- IPs: tagged with tags `malware`, `c2`, `botnet` by multiple vendors

### 5. Censys SSL Certificate Pivot
Queried Censys for SSL certificates on suspect IPs:
- Found shared self-signed certificate across 4 IPs
- Certificate subject: `CN=localhost` — typical of attacker-controlled infrastructure
- Certificate pivot revealed 3 additional IPs not in original scope

### 6. MITRE ATT&CK Mapping

| Technique ID | Technique | Evidence |
|---|---|---|
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP POST to C2 on port 8080 |
| T1071.004 | Application Layer Protocol: DNS | High-frequency DNS queries to attacker resolver |
| T1583.001 | Acquire Infrastructure: Domains | Newly registered domains with shared registrant |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | Bulletproof hosting provider |
| T1102 | Web Service | C2 traffic proxied through legitimate-looking HTTP |

---

## Findings

| Indicator | Type | Verdict | Source |
|---|---|---|---|
| evil-domain[.]net | Domain | Malicious | VirusTotal, Maltego |
| update-cdn[.]com | Domain | Malicious | VirusTotal, passive DNS |
| log-analytics[.]io | Domain | Suspicious (new) | Registrant overlap |
| 91.208.154.112 | IP | Malicious | Shodan, VirusTotal |
| 185.220.101.33 | IP | Malicious | Censys cert pivot |
| 10 additional IPs/domains | Various | Related infrastructure | Maltego transforms |

---

## Intelligence Report Summary

**Campaign Assessment:** High confidence attacker infrastructure cluster. Shared registrant, hosting provider, SSL certificates, and behavioral indicators across 12+ nodes suggest organized threat actor — not commodity malware.

**Threat Actor Profile:** Unknown actor. Infrastructure consistent with persistent access operations. Bulletproof hosting and newly registered domains suggest operational security awareness.

**Recommended Actions:**
- Block all identified IOCs at perimeter firewall and DNS
- Add detection rules for C2 beaconing patterns to Sentinel
- Alert on connections to identified ASN ranges
- Monitor for newly registered domains matching registrant pattern

---

## What I Learned

- Maltego transform chaining is the most efficient way to rapidly expand from a small set of seed indicators to a full infrastructure map
- SSL certificate pivoting via Censys consistently reveals related infrastructure that doesn't appear in passive DNS or VirusTotal lookups
- Newly registered domains with no threat intel history require behavioral analysis — clean reputation alone does not mean safe
- Mapping findings to MITRE ATT&CK at time of investigation makes detection rule development significantly faster

---

## Files

```
threat-intel-investigation/
├── README.md               ← This file
├── ioc-list.csv            ← Full IOC list with verdicts
├── maltego-graph.png       ← Infrastructure relationship graph
└── sentinel-queries/       ← KQL queries used for telemetry review
```
