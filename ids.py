from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict
import time

# Dictionary to track SYN requests per IP and a timestamp to reset counts
syn_counts = defaultdict(int)
start_time = time.time()
SYN_THRESHOLD = 50  # Alert if an IP sends more than 50 SYNs in a short window


def process_packet(packet):
    global start_time

    # Reset our SYN tracker every 10 seconds to avoid false positives over long periods
    if time.time() - start_time > 10:
        syn_counts.clear()
        start_time = time.time()

    # Ensure the packet has an IP layer before analyzing
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Rule 1: Detect abnormally large ICMP packets (Ping of Death indicator)
        if packet.haslayer(ICMP):
            if len(packet) > 1500:
                print(f"[ALERT] Large ICMP packet detected from {src_ip} (Size: {len(packet)} bytes)")

        # Rule 2: Detect potential SYN Floods and Unencrypted Traffic
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]

            # Check if the SYN flag ('S') is set
            if tcp_layer.flags == 'S':
                syn_counts[src_ip] += 1
                if syn_counts[src_ip] > SYN_THRESHOLD:
                    print(f"[ALERT] Possible SYN Flood Attack detected from {src_ip}!")

            # Rule 3: Flag unencrypted sensitive traffic (Ports 20, 21 for FTP; 23 for Telnet)
            if tcp_layer.dport in [20, 21, 23] or tcp_layer.sport in [20, 21, 23]:
                print(f"[WARNING] Unencrypted FTP/Telnet traffic detected: {src_ip} -> {dst_ip}")


def main():
    print("[+] Starting Basic Python IDS...")
    print("[+] Sniffing network traffic. Press Ctrl+C to stop.")

    # Start sniffing.
    # store=False ensures we don't keep packets in RAM, preventing memory exhaustion.
    sniff(prn=process_packet, store=False)


if __name__ == "__main__":
    main()