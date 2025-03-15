# GhostMapper
# GhostMapper

**GhostMapper** is a stealth CLI tool for passive network mapping, designed primarily for red teaming operations. It listens for ARP and ICMP packets to build a real-time network map, offering both immediate feedback and a post-capture summary.

---

## Table of Contents
- [Features](#features)
- [Usage](#usage)
- [Installation](#installation)
- [Architecture](#architecture)
- [Legal Disclaimer](#legal-disclaimer)
- [Contributing](#contributing)
- [License](#license)

---

## Features
- **Passive Sniffing:** No active probes; listens for ARP and ICMP packets.
- **Stealth Mode:** Operates without alerting network defenses.
- **Real-Time Feedback:** Immediately displays discovered IPs and MAC addresses.
- **Tabular Reporting:** Neatly formatted output for easy analysis.

---

## Usage

Run GhostMapper with:
```bash
./ghostmapper.py -i <network_interface> [-c <packet_count>]
