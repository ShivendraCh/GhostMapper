#!/usr/bin/env python3
"""
GhostMapper: A stealth CLI tool for passive network mapping using ARP and ICMP sniffing.
Uses Click for a robust command-line interface.
"""

import click 
import logging
from collections import defaultdict
from scapy.all import sniff, ARP, ICMP, IP

# To suppress scapy warning for a clean CLI output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Global storage: A dictionary mapping IP addresses to a set if MAC address
network_devices = defaultdict(set)

def process_packet(packet):
    """
    Callback function for each captured packet.
    It filters ARP and ICMP packets, extracts the source IP and MAC (if available),
    and updates the global network mapping.
    """
    # Process ARP packets:
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        ip_addr = arp_layer.psrc  # Source IP address of ARP packet
        mac_addr = arp_layer.hwsrc  # Source MAC address of ARP packet
        network_devices[ip_addr].add(mac_addr)
        print(f"Discovered ARP: IP: {ip_addr} at MAC: {mac_addr}")

    # Process ICMP packets: Used to identify active hosts
    if packet.haslayer(ICMP) and packet.haslayer(IP):
        ip_layer = packet[IP]
        ip_src = ip_layer.src  # Source IP from IP layer
        if ip_src not in network_devices:
            network_devices[ip_src] = set()
        print(f"Discovered ICMP packet from: IP: {ip_src}")

def start_sniffing(interface, count):
    """
    Initiates packet sniffing on a designated network interface.
    
    :param interface: The network interface to monitor (e.g., 'eth0').
    :param count: Number of packets to capture; 0 means unlimited.
    """
    print(f"Starting GhostMapper in Stealth Mode on interface: {interface}...")
    
    try:
        # Capture only ARP or ICMP packets using a Berkeley Packet Filter.
        sniff(iface=interface, filter="arp or icmp", prn = process_packet,store =0, count=count)

    except Exception as e:
        print(f"Error while sniffing : {e}")

def display_network_map():
    """
    Displays the discovered network devices in a formatted, tabular layout.
    """
    print("\nNetwork Mapping Results:")
    print("-" * 40)
    print("{:<20} {:<20}".format("IP Address","MAC Addresses"))
    print("-" * 40)
    for ip, mac_set in network_devices.items():
        macs = ", ".join(mac_set) if mac_set else "N/A"
        print("{:<20} {:<20}".format(ip, macs))
    print("-" * 40)

@click.command()
@click.option('-i', '--interface', required=True, help="Network interface to sniff on (e.g., eth0)")
@click.option('-c', '--count', default = 0, help="Number of packets to capture (0 for unlimited)")

def main(interface, count):
    """
    Main entry point for ghostmapper.
    
    Uses Click to parse command-line options, then initiates packet sniffing
    and displays the final network mapping.
    """
    # Start passive packet capture
    start_sniffing(interface, count)

    # After capturing packets, print the discovered network mapping
    display_network_map()

if __name__ == "__main__":
    main()  # Call the main function when the script is run directly.



        




