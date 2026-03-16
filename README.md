# Cybersecurity Portfolio — Alejandro Garcia

**Alias:** CyberJudoSec · Hackth3br0nx  
**Role Target:** Threat Hunting · Blue Team · Cloud Security · Detection Engineering  
**Location:** Forsyth, Georgia  
**Contact:** CyberJudoSec@gmail.com  
**LinkedIn:** [mralejandrogarcia85](https://linkedin.com/in/mralejandrogarcia85)  
**Portfolio Site:** [hackth3br0nx.github.io](https://hackth3br0nx.github.io)  
**TryHackMe:** [Hackth3br0nx](https://tryhackme.com/p/Hackth3br0nx)  
**Threat Hunting Labs:** [hackth3br0nx](https://www.threathuntinglabs.com/u/hackth3br0nx)  

---

## About Me

20 years of operational experience spanning the US Navy, enterprise IT, QA engineering, network engineering, cloud infrastructure, and cybersecurity operations. I evolved from using technology, to understanding it, to building it, to securing and hardening it. I don't wait for alerts to find threats — I hunt them.

Every investigation I run follows the same discipline I learned managing ordnance on a carrier: observe carefully, form a hypothesis, validate with evidence, and never guess.

---

## Core Skills

| Category | Tools & Technologies |
|---|---|
| SIEM & Detection | Microsoft Sentinel, Splunk, Elastic SIEM, KQL, SPL, ES\|QL |
| Threat Intel & OSINT | Maltego, Shodan, VirusTotal, Censys, SpiderFoot, ZeroFox, SecurityTrails |
| Endpoint & Identity | Defender XDR, Okta, Wiz, Forcepoint, Microsoft Entra ID, Active Directory, SAML, OAuth 2.0, MFA, Zero Trust, PAM |
| Cloud Platforms | AWS, Microsoft Azure, Google Cloud Platform, IAM, CloudTrail, Azure Monitor |
| Network Security | Wireshark, nmap, tcpdump, DNS Analysis, Firewall Config, VLAN Segmentation, IDS/IPS |
| Scripting & Analysis | Python, PowerShell, Bash, KQL, Splunk SPL, Regex, JSON Parsing |
| Frameworks | MITRE ATT&CK, NIST CSF, NIST SP 800-53 |

---

## Featured Projects

| # | Project | Key Skills | Status |
|---|---|---|---|
| 01 | [Network Traffic Analysis Lab](./01-network-traffic-analysis/README.md) | Wireshark, DNS, TCP/IP, C2 Detection, PCAP Analysis | ✅ Complete |
| 02 | [Vulnerability Assessment Lab](./02-vulnerability-assessment/README.md) | Nmap, Nessus, CVSS, Risk Prioritization, Remediation | ✅ Complete |
| 03 | [Firewall & Segmentation Lab](./03-firewall-and-segmentation-lab/README.md) | pfSense, VLAN Design, Firewall Rules, nmap Validation | ✅ Complete |
| 04 | [SIEM / Threat Hunting Project](./04-siem-threat-hunting/README.md) | Sentinel, KQL, Splunk SPL, MITRE ATT&CK, Incident Response | ✅ Complete |
| 05 | [Cloud Security Lab](./05-cloud-security-lab/README.md) | AWS, Azure, IAM Hardening, CloudTrail, Storage Security | ✅ Complete |
| 06 | [NIST Security Architecture](./06-nist-security-architecture/README.md) | NIST CSF, NIST 800-53, Risk Assessment, Secure Architecture | ✅ Complete |
| 07 | [Impossible Travel Detection](./07-impossible-travel-detection/README.md) | KQL, Microsoft Sentinel, Defender for Identity, Hypothesis-Based Hunting | ✅ Complete |
| 08 | [Malicious Infrastructure Investigation](./08-threat-intel-investigation/README.md) | Maltego, Shodan, VirusTotal, Censys, MITRE ATT&CK, IOC Analysis | ✅ Complete |

---

## Project Summaries

### 01 — Network Traffic Analysis Lab
Analyzed PCAP files from a simulated enterprise host showing anomalous outbound behavior. Applied Wireshark filters to identify DNS tunneling, C2 beaconing, and Base64-encoded POST payloads. Confirmed dnscat2-style tunneling with 180+ DNS queries/minute to a bulletproof resolver.

**Tools:** Wireshark · tcpdump · Kali Linux  
**Key finding:** DNS tunneling confirmed via subdomain length analysis — C2 channel operating entirely over port 53

---

### 02 — Vulnerability Assessment Lab
Credentialed vulnerability assessment across a 12-asset simulated small business environment. Identified 3 Critical findings including EternalBlue on 6 workstations and default credentials on the firewall. Delivered a prioritized remediation roadmap with 30-day action plan.

**Tools:** Nmap · Nessus Essentials · CVE Database · VirtualBox  
**Key finding:** EternalBlue (CVE-2017-0144, CVSS 9.8) on 6 unpatched workstations — immediate ransomware risk

---

### 03 — Firewall & Network Segmentation Lab
Replaced a flat network with a 3-VLAN segmented architecture using pfSense. Default-deny firewall rules with explicit allow policies. All 5 nmap validation tests passed. Lateral movement fully blocked.

**Tools:** pfSense · VirtualBox · Kali Linux · nmap · Windows 10 VM  
**Key finding:** Default-deny segmentation eliminated unrestricted lateral movement across the environment

---

### 04 — SIEM / Threat Hunting Project
Observation-driven hunt after log review flagged sign-in anomalies. Built KQL impossible travel queries in Sentinel, correlated with Splunk endpoint telemetry. Reconstructed attacker timeline across 3 accounts and 4 workstations. KQL fired 4 hours before Defender for Identity alerted.

**Tools:** Microsoft Sentinel · Splunk · KQL · Defender for Identity · MITRE ATT&CK  
**Key finding:** Proactive KQL hunting detected credential compromise 4 hours before automated alerting fired

---

### 05 — Cloud Security Lab
Assessed and hardened a simulated AWS/Azure environment. Found public S3 buckets, wildcard IAM, disabled CloudTrail. Remediated all 6 critical misconfigurations and enabled multi-region logging.

**Tools:** AWS IAM · S3 · CloudTrail · Azure Defender for Cloud · Azure Monitor  
**Key finding:** Wildcard IAM policy granted unrestricted access to all AWS services — replaced with least-privilege

---

### 06 — NIST Security Architecture Case Study
Assessed a 50-user hybrid company against NIST CSF — baseline maturity 1.2/5. Designed target architecture, mapped 10 controls to NIST SP 800-53, delivered 4-phase roadmap. Projected maturity: 3.8/5.

**Tools:** NIST CSF · NIST SP 800-53 · Microsoft Sentinel · Azure Entra ID · pfSense  
**Key finding:** MFA alone closes the majority of credential-based attack vectors in the assessed environment

---

### 07 — Impossible Travel Detection
Built KQL detection logic in Sentinel for impossible travel login patterns. Correlated with Defender for Identity. Detection fired 4 hours before automated alerts.

**Tools:** Microsoft Sentinel · KQL · Defender for Identity · Azure Entra ID  
**Key finding:** Hypothesis-driven hunting detected compromise before any automated alert fired

---

### 08 — Malicious Infrastructure Investigation
Investigated suspicious domains and IPs in enterprise telemetry. Maltego pivots expanded 3 seed indicators to 12 related infrastructure nodes via shared registrant, hosting, and SSL certificate patterns.

**Tools:** Maltego · Shodan · VirusTotal · Censys · SpiderFoot · Microsoft Sentinel  
**Key finding:** SSL certificate pivoting via Censys revealed 3 additional IPs not present in any other data source

---

## Tools & Platforms

**SIEM:** Microsoft Sentinel · Splunk · Elastic SIEM  
**Endpoint:** Defender XDR · Defender for Endpoint · Defender for Identity · Defender for Office 365  
**Identity:** Okta · Microsoft Entra ID · Active Directory · Wiz · Forcepoint  
**Cloud:** AWS · Microsoft Azure · Google Cloud Platform  
**OSINT:** Maltego · Shodan · VirusTotal · Censys · SpiderFoot · ZeroFox · SecurityTrails  
**Network:** Wireshark · nmap · tcpdump · pfSense  
**Scripting:** Python · PowerShell · Bash · KQL · Splunk SPL  
**OS:** Kali Linux · Ubuntu · Windows Server · REMnux · macOS  

---

## Certifications

| Certification | Issuer |
|---|---|
| Certified Ethical Hacker (CEH) | EC-Council |
| GIAC Security Essentials (GSEC) | GIAC |
| GIAC Foundational Cybersecurity Technologies (GFACT) | GIAC |
| Security+ | CompTIA |
| Network+ | CompTIA |
| A+ | CompTIA |
| Infrastructure Specialist | CompTIA |
| Operations Specialist | CompTIA |
| Solutions Architect Associate | AWS |
| Cloud Practitioner | AWS |
| Azure Administrator AZ-104 | Microsoft |
| Azure Fundamentals AZ-900 | Microsoft |
| CCNA | Cisco |
| Certified Professional | Okta |

---

## Education

**Trident University International**  
Associate of Science — Cybersecurity (2023)  
Bachelor of Science — Computer Science (Expected 2026)  

---

## What I'm Working On Now

- Completing Threat Hunting Labs investigations using Splunk SPL and Elastic ES|QL
- Building a reusable KQL detection query library from real intrusion telemetry
- Expanding DevSecOps skills via Codefinity
- Adding write-ups for OSINT investigations and TryHackMe threat hunting rooms

---

*This portfolio is proof of decisions, not just credentials. Every project documents a scenario, an objective, the exact tools and actions taken, and what was found or built. If it doesn't show how I think, it doesn't belong here.*
