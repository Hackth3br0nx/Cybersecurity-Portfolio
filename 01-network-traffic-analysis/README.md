# 01 — Network Traffic Analysis Lab

**Analyst:** Alejandro Garcia (CyberJudoSec)  
**Tools:** Wireshark · tcpdump · Kali Linux  
**Skills:** Packet Analysis · DNS Analysis · C2 Detection · TCP/IP · HTTP/HTTPS Traffic  
**Difficulty:** Intermediate  

---

## Scenario

A simulated enterprise environment generated unusual network traffic. Packet captures were collected from a host exhibiting anomalous behavior — high-frequency DNS queries to an external resolver and outbound connections over non-standard ports. The task was to analyze the captures, identify whether malicious activity was present, and document findings for the detection team.

---

## Objective

- Analyze raw PCAP files for signs of malicious network activity
- Identify C2 communication patterns, DNS tunneling, and suspicious connections
- Document what normal traffic looks like vs. what suspicious traffic looks like
- Produce detection notes usable by a SOC analyst

---

## Tools Used

| Tool | Purpose |
|---|---|
| Wireshark | Primary packet capture analysis |
| tcpdump | Command-line capture and filtering |
| Kali Linux | Analysis environment |
| dns.py (custom) | DNS query frequency analysis |

---

## Steps Performed

### 1. Capture Collection
Loaded PCAP files into Wireshark. Applied baseline display filters to establish normal traffic baseline:
```
dns || http || tcp.flags.syn == 1
```

### 2. DNS Traffic Analysis

[DNS tunnel path diagram](./diagrams/dns-tunnel-diagram.png)

Filtered for DNS traffic and examined query patterns:
```
dns.qry.name contains "." && dns.flags.response == 0
```
**Observed:** High-frequency queries to a single external resolver. Subdomain strings were unusually long (avg 52 chars), consistent with DNS tunneling behavior.

### 3. TCP/IP Analysis
Examined SYN packets for port distribution:
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```
**Observed:** Repeated SYN attempts to port 4444 and 8080 on external IPs — common C2 ports.

### 4. HTTP Traffic Review
```
http.request.method == "GET" || http.request.method == "POST"
```
**Observed:** POST requests with Base64-encoded payloads in the body — consistent with data staging or exfiltration.

### 5. C2 Beaconing Pattern
Calculated interval between outbound connections to a single external IP. Intervals were consistent (every ~60 seconds) — hallmark of automated C2 beaconing.

---

## Findings

| Finding | Severity | Description |
|---|---|---|
| DNS Tunneling | High | Long subdomain strings at high frequency to external resolver |
| C2 Beaconing | High | Regular 60-second intervals to external IP on port 4444 |
| Encoded POST Requests | Medium | Base64-encoded data in HTTP POST body |
| Unusual Port Activity | Medium | Outbound SYN to non-standard ports 4444, 8080 |

---

## Detection Notes

**What normal DNS traffic looks like:**
- Short query strings (domain.tld)
- Low frequency (< 10 queries/min per host)
- Queries to known resolvers (8.8.8.8, 1.1.1.1)

**What suspicious DNS traffic looks like:**
- Long randomized subdomains (50+ chars)
- High frequency bursts (100+ queries/min)
- Consistent single external resolver not in corporate baseline

**C2 Beaconing indicators:**
- Regular time intervals between outbound connections
- Same destination IP/port repeated
- Small consistent packet sizes

---

## Remediation

- Block outbound DNS to all resolvers except approved corporate DNS
- Alert on DNS queries with subdomain length > 40 characters
- Block outbound connections on ports 4444, 8080 at perimeter
- Implement DNS logging and monitor for query frequency anomalies

---

## What I Learned

- DNS tunneling produces distinctive subdomain length and frequency patterns detectable with Wireshark filters
- C2 beaconing intervals are often consistent enough to detect via statistical analysis of connection timestamps
- HTTP POST body encoding is a common exfiltration technique that can be caught with content inspection rules
- Establishing a normal traffic baseline first makes anomalies significantly easier to identify

---

## Files

```
01-network-traffic-analysis/
├── README.md               ← This file
├── pcaps/                  ← Packet capture files
├── screenshots/            ← Wireshark annotated screenshots
└── notes.md                ← Raw investigation notes
```
