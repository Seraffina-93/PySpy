import json
import socket
from scapy.all import sr1, IP, TCP


def syn_scan(ip, ports):
    open_ports = []
    for port in ports:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
    return open_ports


def tcp_connect_scan(ip, ports):
        # Load configuration
    with open('config.json', 'r') as config_file:
        config = json.load(config_file)
    
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(config["timeout"])
        result = sock.connect_ex((ip, port))
        if not result:
            open_ports.append(port)
        sock.close()
    return open_ports