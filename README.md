# Packet-Sniffer-Tool
A packet sniffer is a tool used for monitoring and analyzing network traffic by intercepting data packets as they traverse a network. It can capture and log the details of various network protocols (e.g., TCP, UDP, HTTP, etc.), and is often used for network diagnostics, troubleshooting, security monitoring, and even by attackers to eavesdrop on data.

# How This Code Works 
This code implements a TCP Packet Sniffer using Python and the Scapy library. Here's a brief rundown of how the code works:

1. Initialization: The class PacketSniffer is initialized with parameters for network interface (eth0 by default), a text log file (tcp_packet_log.txt), and a CSV log file (tcp_packet_log.csv).
   
2. Packet Sniffing: The sniff_packets method opens a raw socket to capture Ethernet frames, binds it to the specified network interface, and starts sniffing packets.

3. Packet Parsing: When a TCP packet is captured, the packet is analyzed to extract information such as:
**Timestamp
Source and Destination MAC addresses
Source and Destination IP addresses
Source and Destination Ports
Protocol (TCP)
Payload (data inside the packet)
HTTP headers (if present)**


4. Logging: The packet data is logged in two formats:

5. Text format: Captures the packet information in a human-readable format.
   
6. CSV format: Logs packet data in a structured format for later analysis.

7. Payload Extraction: If the packet contains payload data (e.g., HTTP request data), it is extracted and logged. If the data is HTTP, the HTTP headers are parsed and logged.
The process continues until the user interrupts it (via CTRL+C), at which point the sniffer stops.

# Uses of This Code
The TCP Packet Sniffer can be used for various purposes, including:

Network Troubleshooting, Security Monitoring, Network Forensics, Performance Analysis, Educational Purposes

# How to Implement and Use This Code

To use this packet sniffer on your system, follow these steps:

**Requirements:**

1. Python 3.x: Ensure Python is installed on your system.
2. Scapy Library: Install the Scapy library, which is used for packet manipulation and analysis.
3. Root/Administrator Access: Sniffing raw packets typically requires root or administrator privileges. Run the script with appropriate permissions.

# Implementation Steps:

1. Clone or Copy the Code:

Copy the provided code into a Python file, for example packet_sniffer.py.

2. Run the Sniffer Script:

Open a terminal and navigate to the directory where the script is saved.
Run the script with root or administrator privileges:

3. View the Logs:

The packet sniffer will create two log files:
tcp_packet_log.txt: Contains the packet information in a human-readable format.
tcp_packet_log.csv: Contains structured packet data (timestamp, MAC addresses, IP addresses, etc.).
These logs will be appended with each packet capture.

4. Stop Sniffing:

To stop the sniffing process, press CTRL+C in the terminal.


# Enhancements to Improve the Code
There are several enhancements you can make to improve the functionality and usability of the packet sniffer:

Filter Specific Packets, Support for Other Protocols, Packet Filtering and Alerts, Real-Time Dashboard, Store Payloads Securely
