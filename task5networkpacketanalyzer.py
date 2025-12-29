#!/usr/bin/env python3
# Simple educational packet sniffer using Scapy
# Use ONLY on networks you own or have explicit permission to test.

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

def process_packet(pkt):
    # Only process packets that have an IP layer
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Detect protocol
        proto = "OTHER"
        if TCP in pkt:
            proto = "TCP"
            l4 = pkt[TCP]
            sport = l4.sport
            dport = l4.dport
        elif UDP in pkt:
            proto = "UDP"
            l4 = pkt[UDP]
            sport = l4.sport
            dport = l4.dport
        elif ICMP in pkt:
            proto = "ICMP"
            sport = dport = None
        else:
            sport = dport = None

        # Extract payload if present
        payload_str = ""
        if Raw in pkt:
            raw_data = bytes(pkt[Raw].load)
            # Decode safely to avoid errors with binary data
            try:
                payload_str = raw_data.decode("utf-8", errors="replace")
            except Exception:
                payload_str = repr(raw_data)

            # Limit output length for readability
            payload_str = payload_str[:200]

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print("=" * 80)
        print(f"[{timestamp}] Protocol: {proto}")
        print(f"Source IP:      {src_ip}")
        print(f"Destination IP: {dst_ip}")

        if sport is not None and dport is not None:
            print(f"Source Port:    {sport}")
            print(f"Destination Port:{dport}")

        if payload_str:
            print("- Payload (first 200 chars) -")
            print(payload_str)
        else:
            print("- No application payload -")

def main():
    print("Educational Packet Sniffer")
    print("Use ONLY on networks you own or have explicit permission to monitor.")
    print("Press Ctrl+C to stop.\n")

    # filter example: "tcp", "udp", "icmp", "port 80", etc.
    # Empty filter captures everything (may require root privileges).
    bpf_filter = ""   # e.g. "tcp or udp"

    # iface=None means default interface. Set explicitly if needed, e.g. "eth0" or "wlan0".
    sniff(filter=bpf_filter,
          prn=process_packet,
          store=False)

if __name__ == "__main__":
    main()