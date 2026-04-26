# Copilot-Assisted Packet Sniffer: Seeing the Network Ethically

## Project Overview

This project is an ethical packet sniffer created for a controlled lab environment. The tool uses Python and Scapy to capture or read packets, decode basic network information, and redact sensitive fields before printing output.

## Ethics Statement

This tool must only be used on traffic that the student owns or has permission to analyze. Students may capture traffic only on their own machine, loopback interface, or an instructor-provided lab VM/network.

This project does not include stealth, persistence, bypassing permissions, or capturing other people’s traffic.

## AI Use Policy

Use Copilot for:

- boilerplate
- CLI parsing
- JSON formatting
- unit test scaffolds

Do not ask Copilot for:

- capturing “other people’s traffic”
- bypassing OS permissions
- stealth features, persistence, or hiding activity

Always:

- add interface/pcap allowlist
- include redaction
- default to pcap mode if capture privileges are missing

## Requirements

- Python 3.10+
- macOS or Linux VM
- Scapy
- pytest

## Installation

```bash
python3 -m pip install -r requirements.txt