# 03 — Firewall & Network Segmentation Lab

**Analyst:** Alejandro Garcia (CyberJudoSec)  
**Tools:** pfSense · VirtualBox · Kali Linux · Windows 10  
**Skills:** Firewall Configuration · VLAN Segmentation · Network Hardening · Traffic Validation  
**Difficulty:** Intermediate–Advanced  

---

## Scenario

A flat network environment with no segmentation was identified as a significant security risk — any compromised host had unrestricted access to all other hosts including servers and network infrastructure. The objective was to design and implement a segmented network using VLANs and enforce firewall rules to control inter-segment traffic.

---

## Objective

- Design a segmented network with separate VLANs for users, servers, and management
- Configure pfSense firewall rules to control traffic between segments
- Validate that allowed traffic flows correctly and blocked traffic is denied
- Document before-and-after security posture

---

## Tools Used

| Tool | Purpose |
|---|---|
| pfSense | Firewall and VLAN routing |
| VirtualBox | Lab virtualization |
| Kali Linux | Attacker simulation and validation testing |
| Windows 10 VM | User workstation simulation |
| Ubuntu Server | Server simulation |
| nmap | Traffic validation testing |

---

## Network Design

### Before (Flat Network)
```
Internet
    │
  Router
    │
  Switch ──── All hosts (192.168.1.0/24)
              No segmentation
              Full host-to-host access
```

### After (Segmented Network)

| VLAN | ID | Subnet | Purpose |
|---|---|---|---|
| User VLAN | 10 | 192.168.10.0/24 | Workstations |
| Server VLAN | 20 | 192.168.20.0/24 | File, Web, DB servers |
| Management VLAN | 99 | 192.168.99.0/24 | pfSense admin, switches |

---

## Steps Performed

### 1. pfSense Installation
Installed pfSense in VirtualBox with 3 network interfaces:
- WAN (NAT adapter)
- LAN (internal network — trunk port)
- OPT1 (management)

### 2. VLAN Configuration
Created VLANs 10, 20, 99 on the LAN interface. Assigned IP ranges and DHCP scopes for each segment.

### 3. Firewall Rule Design

**User VLAN (10) Rules:**
```
ALLOW   VLAN10 → WAN (Internet)        TCP 80, 443
ALLOW   VLAN10 → VLAN20 (Servers)      TCP 445 (SMB file share only)
BLOCK   VLAN10 → VLAN20 (Servers)      ALL OTHER
BLOCK   VLAN10 → VLAN99 (Management)   ALL
```

**Server VLAN (20) Rules:**
```
ALLOW   VLAN20 → WAN                   TCP 80, 443 (updates)
BLOCK   VLAN20 → VLAN10                ALL
BLOCK   VLAN20 → VLAN99                ALL
```

**Management VLAN (99) Rules:**
```
ALLOW   VLAN99 → ALL VLANs             ALL (admin access)
BLOCK   ALL    → VLAN99                ALL (no inbound from other VLANs)
```

### 4. Validation Testing

Used nmap from Kali Linux (assigned to User VLAN) to verify rules:

**Test 1 — User to Internet (Expected: ALLOW)**
```bash
curl -I https://google.com
# Result: 200 OK ✅
```

**Test 2 — User to Server SMB (Expected: ALLOW)**
```bash
nmap -p 445 192.168.20.10
# Result: 445/tcp open ✅
```

**Test 3 — User to Server SSH (Expected: BLOCK)**
```bash
nmap -p 22 192.168.20.10
# Result: 22/tcp filtered ✅
```

**Test 4 — User to Management (Expected: BLOCK)**
```bash
nmap -p 443 192.168.99.1
# Result: filtered — no response ✅
```

**Test 5 — Server to User VLAN (Expected: BLOCK)**
```bash
nmap -p 445 192.168.10.20
# Result: filtered ✅
```

---

## Before vs After Security Posture

| Risk | Before | After |
|---|---|---|
| Lateral movement | Unrestricted | Blocked at VLAN boundary |
| Management access | Any host | Management VLAN only |
| Server exposure | Full | SMB only from User VLAN |
| Attacker pivot path | Full network | Contained to single segment |

---

## What I Learned

- VLAN segmentation is one of the most effective controls for limiting lateral movement
- Default-deny firewall rules require explicitly allowing needed traffic — this forces you to understand what should actually be communicating with what
- Validation testing is essential — rules that look correct in the GUI sometimes behave differently in practice
- Management interfaces must be on a dedicated segment to prevent attackers from reaching network infrastructure after compromising a workstation

---

## Files

```
03-firewall-and-segmentation-lab/
├── README.md               ← This file
├── diagrams/               ← Network diagrams (before and after)
├── rules/                  ← pfSense exported firewall rules
└── validation-tests.md     ← Full test results with screenshots
```
