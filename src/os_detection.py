import subprocess


def os_detection(ip_address):
    try:
        # Run a ping command and capture the output
        ping_output = subprocess.Popen(['ping', '-c', '1', '-w', '2', ip_address],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)

        # Extract the TTL value from the ping output
        output = ping_output.communicate()[0].decode('utf-8')
        ttl = None
        for line in output.split('\n'):
            if "ttl=" in line:
                try:
                    ttl = int(line.split("ttl=")[1].split()[0])
                    break
                except ValueError:
                    continue

        if ttl is None:
            return "Unknown"

        # Determine the operating system based on the TTL value
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Other Unix"

        return "Unknown"

    except Exception as e:
        print(f"Error while detecting OS for {ip_address}: {e}")
        return "Unknown"
