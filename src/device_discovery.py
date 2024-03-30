import socket
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.all import srp, sr1


def discover_devices():
    devices = []

    # Perform ARP ping to find devices
    arp_ping = ARP(pdst="192.168.0.1/24")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_ping
    result = srp(packet, timeout=3, verbose=False)[0]
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    # Perform TCP ping to test connection
    for device in devices:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((device["ip"], 80)) == 0
            device["tcp_ping"] = result
        except Exception:
            device["tcp_ping"] = False
        sock.close()

    # Perform UDP ping to test connection
    for device in devices:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        try:
            sock.sendto(b"PING", (device["ip"], 80))
            data, _ = sock.recvfrom(1024)
            if data == b"PONG":
                device["udp_ping"] = True
            else:
                device["udp_ping"] = False
        except Exception:
            device["udp_ping"] = False
        sock.close()

    # Perform ICMP ping to test connection
    for device in devices:
        ping = IP(dst=device["ip"]) / ICMP()
        result = sr1(ping, timeout=1, verbose=False)
        if result:
            device["icmp_ping"] = True
        else:
            device["icmp_ping"] = False

    return devices