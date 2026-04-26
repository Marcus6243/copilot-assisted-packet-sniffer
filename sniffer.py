#!/usr/bin/env python3

import argparse
import json
import re
from datetime import datetime
from scapy.all import sniff, rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw


ALLOWED_INTERFACES = ["lo0", "lo", "eth0", "wlan0", "en0"]
ALLOWED_PCAP_EXTENSIONS = [".pcap", ".pcapng"]


def mask_ip(ip_address):
    if not ip_address:
        return None

    parts = ip_address.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".xxx"

    return "[REDACTED_IP]"


def redact_sensitive_text(text):
    if not text:
        return text

    text = re.sub(
        r"Authorization:\s*.*",
        "Authorization: [REDACTED_AUTH]",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"Cookie:\s*.*",
        "Cookie: [REDACTED_COOKIE]",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"[\w\.-]+@[\w\.-]+\.\w+",
        "[REDACTED_EMAIL]",
        text,
    )

    text = re.sub(
        r"([?&](password|token|session|apikey|api_key)=)[^&\s]+",
        r"\1[REDACTED_SECRET]",
        text,
        flags=re.IGNORECASE,
    )

    return text


def decode_http(packet):
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors="ignore")
            payload = redact_sensitive_text(payload)

            first_line = payload.split("\r\n")[0]

            if first_line.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")):
                host_match = re.search(r"Host:\s*(.*)", payload, re.IGNORECASE)
                host = host_match.group(1).strip() if host_match else None

                return {
                    "http_request_line": first_line,
                    "host": host,
                }
        except Exception:
            return None

    return None


def decode_packet(packet):
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "dns_query": None,
        "http": None,
    }

    if packet.haslayer(IP):
        event["src_ip"] = mask_ip(packet[IP].src)
        event["dst_ip"] = mask_ip(packet[IP].dst)

    if packet.haslayer(TCP):
        event["protocol"] = "TCP"
        event["src_port"] = packet[TCP].sport
        event["dst_port"] = packet[TCP].dport
        event["http"] = decode_http(packet)

    elif packet.haslayer(UDP):
        event["protocol"] = "UDP"
        event["src_port"] = packet[UDP].sport
        event["dst_port"] = packet[UDP].dport

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            dns_name = packet[DNSQR].qname.decode(errors="ignore")
            event["dns_query"] = redact_sensitive_text(dns_name)
        except Exception:
            event["dns_query"] = "[DNS_DECODE_ERROR]"

    return event


def print_packet(packet):
    decoded = decode_packet(packet)
    print(json.dumps(decoded, indent=2))


def validate_interface(interface):
    if interface and interface not in ALLOWED_INTERFACES:
        raise ValueError(
            f"Interface '{interface}' is not allowed. "
            f"Allowed interfaces: {ALLOWED_INTERFACES}"
        )


def validate_pcap_file(pcap_file):
    if not any(pcap_file.endswith(ext) for ext in ALLOWED_PCAP_EXTENSIONS):
        raise ValueError("Only .pcap or .pcapng files are allowed.")


def run_live_capture(interface, packet_filter, count):
    validate_interface(interface)

    print("[INFO] Starting live capture.")
    print("[INFO] Only capture traffic you own or have permission to analyze.")
    print(f"[INFO] Interface: {interface}")
    print(f"[INFO] Filter: {packet_filter}")
    print(f"[INFO] Count: {count}")

    sniff(
        iface=interface,
        filter=packet_filter,
        prn=print_packet,
        count=count,
        store=False,
    )


def run_pcap_mode(pcap_file):
    validate_pcap_file(pcap_file)

    print("[INFO] Reading packets from PCAP file.")
    packets = rdpcap(pcap_file)

    for packet in packets:
        print_packet(packet)


def main():
    parser = argparse.ArgumentParser(
        description="Ethical packet sniffer for lab traffic only."
    )

    parser.add_argument(
        "--mode",
        choices=["live", "pcap"],
        default="pcap",
        help="Choose live capture or pcap reading mode.",
    )

    parser.add_argument(
        "--iface",
        default="lo0",
        help="Network interface to sniff on. Example: lo0, lo, eth0, wlan0, en0.",
    )

    parser.add_argument(
        "--filter",
        default="udp port 53 or tcp port 80",
        help='BPF filter. Example: "udp port 53" or "tcp port 80".',
    )

    parser.add_argument(
        "--count",
        type=int,
        default=25,
        help="Number of packets to capture.",
    )

    parser.add_argument(
        "--pcap",
        help="Path to a .pcap or .pcapng file.",
    )

    args = parser.parse_args()

    try:
        if args.mode == "live":
            run_live_capture(args.iface, args.filter, args.count)

        elif args.mode == "pcap":
            if not args.pcap:
                print("[ERROR] PCAP mode requires --pcap sample.pcap")
                return

            run_pcap_mode(args.pcap)

    except PermissionError:
        print("[ERROR] Permission denied. Try PCAP mode or run with proper lab permission.")
    except Exception as error:
        print(f"[ERROR] {error}")


if __name__ == "__main__":
    main()
