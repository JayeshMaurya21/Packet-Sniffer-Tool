import socket
from scapy.all import *
import datetime
import csv

class PacketSniffer:
    def __init__(self, interface="eth0", log_file="tcp_packet_log.txt", csv_file="tcp_packet_log.csv"):
        self.interface = interface
        self.log_file = log_file
        self.csv_file = csv_file
        with open(self.csv_file, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Source MAC", "Destination MAC", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Payload Data", "HTTP Headers"])

    def log_packet_text(self, data):
        with open(self.log_file, "a") as file:
            file.write(data + "\n")

    def log_packet_csv(self, timestamp, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, payload_data, http_headers):
        with open(self.csv_file, "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, payload_data, http_headers])

    # This will display packet information
    def display_packet_info(self, packet_info):
        print(packet_info)


    def extract_http_headers(self, payload_data):
        if payload_data.startswith("GET") or payload_data.startswith("POST"):
            headers = payload_data.split("\r\n")
            return " | ".join(headers)
        return "No HTTP Headers"

    def sniff_packets(self):
        
        sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sniffer_socket.bind((self.interface, 0))

        print(f"Starting packet sniffer on interface '{self.interface}'...")

        try:
            while True:
                raw_data, addr = sniffer_socket.recvfrom(65535)

                
                packet = Ether(raw_data)

                
                if IP in packet and TCP in packet:
                    ip_layer = packet[IP]
                    tcp_layer = packet[TCP]

                    # Info about the packet you want
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    src_mac = packet.src
                    dst_mac = packet.dst
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    protocol = "TCP"

                    packet_info = (
                        f"Timestamp: {timestamp}\n"
                        f"Ethernet Frame: {src_mac} -> {dst_mac}\n"
                        f"IP Packet: {src_ip} -> {dst_ip}, Protocol: {protocol}\n"
                        f"TCP Segment: Source Port: {src_port}, Dest Port: {dst_port}\n"
                    )

                    payload_data = "No payload"
                    http_headers = "No HTTP Headers"

                    # Check if the packet has a data (payload) then it will display
                    if Raw in tcp_layer:
                        payload_data = tcp_layer[Raw].load.decode(errors="ignore")
                        packet_info += f"Payload Data: {payload_data}\n"

                     
                        http_headers = self.extract_http_headers(payload_data)
                        if http_headers != "No HTTP Headers":
                            packet_info += f"HTTP Headers: {http_headers}\n"

                        packet_info += "-" * 80

                
                        self.display_packet_info(f"\n[ALERT] Data Found:\n{packet_info}")

                    else:
                        packet_info += "Payload Data: No payload\n"
                        packet_info += "-" * 80

                    self.log_packet_text(packet_info)

                    
                    self.log_packet_csv(timestamp, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, payload_data, http_headers)

        except KeyboardInterrupt:
            print("\nStopping packet capture.")
            sniffer_socket.close()



if __name__ == "__main__":
    
    sniffer = PacketSniffer(interface="eth0", log_file="tcp_packet_log.txt", csv_file="tcp_packet_log.csv")

    
    sniffer.sniff_packets()
