import json
import requests
import ssl
import socket

def banner_grabbing(target, port):
    # Load configuration
    with open('config.json', 'r') as config_file:
        config = json.load(config_file)
    try:
        certificate = None
        context = ssl.create_default_context()
        if port == 443:
            url = f"https://{target}"
            with context.wrap_socket(socket.socket(), server_hostname=target) as s:
                s.settimeout(config["timeout"])
                try:
                    s.connect((target, 443))
                    certificate = s.getpeercert()
                except Exception as e:
                    return f"Error connecting to target: {e}"
        elif port == 80:
            url = f"http://{target}"
        else:
            url = f"http://{target}:{port}"

        try:
            response = requests.get(url, timeout=5, cert=certificate)
            server_header = response.headers.get("Server")
            if not server_header:
                return "No Server header found"
            return server_header
        except requests.RequestException as e:
            return f"Error connecting to target: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"
