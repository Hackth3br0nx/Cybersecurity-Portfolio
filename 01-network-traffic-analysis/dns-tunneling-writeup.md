# DNS Tunneling Detection · Wireshark + Kali Linux

**Analyst:** Alejandro Garcia (CyberJudoSec)  
**Tools:** Wireshark · tcpdump · Kali Linux  
**Skills:** Packet Analysis · DNS Analysis · C2 Detection · Network Forensics · PCAP Analysis  
**Difficulty:** Intermediate  

---

## Scenario

Packet captures collected from a monitored enterprise host showed unusual DNS traffic patterns — high-frequency queries to a single external resolver, abnormally long subdomain strings, and consistent outbound communication that did not match any known business application. No firewall alert had fired. The hypothesis: a threat actor was using DNS tunneling as a covert C2 channel to exfiltrate data or maintain persistence while evading perimeter controls.

---

## Goal

Confirm whether DNS tunneling was present, identify the exfiltration mechanism, document the indicators for detection, and produce Wireshark filter signatures reusable by SOC analysts.

---

## Tools Used

| Tool | Purpose |
|---|---|
| Wireshark | Primary PCAP analysis and display filtering |
| tcpdump | Command-line capture and initial triage |
| Kali Linux | Analysis environment |
| Python (scapy) | DNS query frequency analysis script |

---

## Actions

### 1. Initial PCAP Triage with tcpdump
```bash
tcpdump -r capture.pcap -n 'port 53' | head -50
```
Immediately observed high-frequency DNS queries from a single internal host (`192.168.1.45`) to an external resolver (`185.220.101.33`) not in the corporate DNS baseline.

### 2. Load PCAP into Wireshark
Opened `capture.pcap` in Wireshark on Kali Linux. Applied initial filter to isolate DNS traffic:
```
dns
```
**Observed:** 847 DNS queries in a 4-minute window from one host. Normal DNS activity for a workstation: typically 5–20 queries per minute.

### 3. Analyze Subdomain Length
```
dns.qry.name contains "." && dns.flags.response == 0
```
**Observed:** Query subdomain strings averaging 52–68 characters in length. Examples:
```
aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.attacker-domain.com
dGhpcyBpcyBiYXNlNjQgZW5jb2RlZCBkYXRh.attacker-domain.com
```
The subdomains were clearly Base64-encoded strings — a hallmark of DNS tunneling tools like `dnscat2` or `iodine`.

### 4. Query Frequency Analysis
```
dns.qry.name contains "attacker-domain.com"
```
Applied Statistics → IO Graph in Wireshark. DNS query rate to `attacker-domain.com`:
- Peak: 212 queries/minute
- Consistent rate: ~180 queries/minute over 4-minute window
- No corresponding legitimate traffic to this domain in corporate DNS logs

### 5. Response Payload Analysis
Examined DNS TXT record responses:
```
dns.qry.type == 16
```
**Observed:** TXT record responses contained Base64-encoded payloads averaging 189 bytes — far exceeding normal TXT record usage. Decoded sample:
```
aGVsbG8gd29ybGQ= → "hello world" (test payload)
```
Confirms bidirectional data transfer via DNS — consistent with a C2 tunnel, not just beaconing.

### 6. C2 Beacon Pattern Analysis
Filtered outbound SYN packets to confirm no secondary C2 channel:
```
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 185.220.101.33
```
**Observed:** No TCP C2 connections. All attacker communication was exclusively via DNS — confirming DNS-only tunneling, likely to evade firewall rules blocking direct TCP C2.

### 7. Resolver Identification
```
dns.flags.response == 1 && ip.src == 185.220.101.33
```
Confirmed `185.220.101.33` was acting as authoritative resolver for `attacker-domain.com`. Queried in Shodan:
- Port 53 open
- No reverse DNS
- Associated with known Tor exit node ranges
- VirusTotal: flagged by 4 vendors as malicious infrastructure

---

## Findings

| Indicator | Type | Description |
|---|---|---|
| `attacker-domain.com` | Domain | DNS tunnel endpoint — authoritative domain |
| `185.220.101.33` | IP | External DNS resolver / C2 infrastructure |
| Base64 subdomains 50+ chars | Behavioral | Data encoding via subdomain strings |
| 180+ DNS queries/min | Behavioral | High-frequency tunneling traffic |
| DNS TXT record payloads | Behavioral | Bidirectional data transfer via TXT responses |

---

## Detection Notes

### What Normal DNS Traffic Looks Like
- Short query strings (domain.tld or subdomain.domain.tld)
- Low frequency: typically < 20 queries/minute per host
- Queries to known corporate resolvers (8.8.8.8, 1.1.1.1, internal DNS)
- TXT record queries rare and small

### What DNS Tunneling Looks Like
- Subdomain strings 40+ characters, often Base64 or hex encoded
- High query frequency (100+ queries/minute) to single external resolver
- Consistent resolver not in corporate DNS baseline
- TXT record responses with large encoded payloads
- No corresponding HTTP/HTTPS traffic to same destination

### Wireshark Detection Filters
```
# Long subdomain detection (potential tunneling)
dns.qry.name matches "[a-zA-Z0-9+/]{40,}\\."

# High-frequency DNS to single resolver (apply Statistics > IO Graph)
dns && ip.dst == 185.220.101.33

# TXT record responses with large payloads
dns.qry.type == 16 && dns.resp.len > 100
```

---

## Likely Tool Identification

Based on traffic signatures:
- Query frequency and subdomain encoding pattern consistent with **dnscat2**
- TXT record response structure matches dnscat2 server response format
- Bidirectional tunnel (not just beacon) — rules out simpler DNS beacon tools

---

## MITRE ATT&CK Mapping

| Technique ID | Technique | Evidence |
|---|---|---|
| T1071.004 | Application Layer Protocol: DNS | All C2 via DNS queries/responses |
| T1048.003 | Exfiltration Over Unencrypted Protocol | Data encoded in DNS subdomains |
| T1041 | Exfiltration Over C2 Channel | Bidirectional tunnel via DNS |
| T1568.002 | Dynamic Resolution: Domain Generation | Encoded subdomains mimic DGA patterns |

---

## Remediation

- Block outbound DNS to all resolvers except approved corporate DNS servers
- Alert on DNS queries with subdomain length > 40 characters
- Alert on any single host exceeding 60 DNS queries/minute to external resolvers
- Enable DNS logging and forward to SIEM for baseline analysis
- Inspect DNS TXT record responses for encoded payloads > 100 bytes

---

## What I Learned

- DNS tunneling produces three consistent signatures: subdomain length, query frequency, and TXT record payload size — any one alone may be noisy, but all three together is high-confidence
- Wireshark's Statistics → IO Graph is the fastest way to visualize query frequency anomalies over time
- Confirming the resolver is not in corporate DNS baseline is a critical first step — it immediately separates attacker infrastructure from legitimate CDN/cloud traffic
- Decoding subdomain strings in real captures is the most definitive confirmation — if the decoded content makes sense as data, it's a tunnel

---

## Files

```
01-network-traffic-analysis/
├── README.md               ← This file
├── pcaps/                  ← Packet capture files
├── screenshots/            ← Annotated Wireshark screenshots
└── notes.md                ← Raw investigation notes and filter library
```
