# GhostMapper

**GhostMapper** is a stealth CLI tool for passive network mapping, engineered for ethical hacking and red teaming engagements. It leverages the power of Python, Scapy, and Click to passively capture network traffic, extract device information, and provide real-time insights—all without generating active probes.

---

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Architecture](#architecture)
- [Enhancements & Future Work](#enhancements--future-work)
- [Contributing](#contributing)
- [Legal Disclaimer](#legal-disclaimer)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Overview

GhostMapper is designed as a passive network mapping tool for red teaming and ethical hacking. By listening for ARP and ICMP packets, the tool identifies active hosts and gathers critical network details, all while maintaining a minimal footprint to avoid detection. Its simplicity and modular design make it a valuable addition to any cybersecurity professional's toolkit.

---

## Features

- **Passive Sniffing:** Listens for ARP and ICMP packets to discover network devices without active scanning.
- **Real-Time Feedback:** Immediately displays discovered IPs and MAC addresses to the console.
- **Tabular Reporting:** Aggregates and presents the network map in a clear, formatted table.
- **Stealth Mode:** Operates without generating additional network traffic, ensuring discreet reconnaissance.
- **Modular Architecture:** Easily maintainable and extendable for future improvements.

---

## Installation

1. **Clone the Repository:**

    ```bash
    git clone https://github.com/yourusername/GhostMapper.git
    cd GhostMapper
    ```

2. **Install Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

    *Dependencies include:*
    - [Scapy](https://scapy.net/)
    - [Click](https://click.palletsprojects.com/)

3. **Permissions:**  
   Running GhostMapper might require elevated privileges. Use `sudo` if necessary.

---

## Usage

Execute GhostMapper with the following command:

```bash
./ghostmapper.py -i <network_interface> [-c <packet_count>]
