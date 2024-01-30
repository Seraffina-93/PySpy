from scapy.all import sr1, IP, TCP

def ack_scan(ip, ports, timeout=1):
    open_ports = []
    try:
        for port in ports:
            packet = IP(dst=ip) / TCP(dport=port, flags="A")
            response = sr1(packet, timeout=timeout, verbose=True)
            if (
                response
                and response.haslayer(TCP)
                and response.getlayer(TCP).flags == 0x4
            ):
                # Port is unfiltered
                open_ports.append(port)
            else:
                print("No response")
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    return open_ports