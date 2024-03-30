import requests


def http_header_evaluation(target):
    try:
        response = requests.head(f"https://{target}", timeout=1)
    except requests.exceptions.SSLError:
        response = requests.head(f"http://{target}", timeout=1)
    except (
        requests.exceptions.Timeout,
        requests.exceptions.ConnectionError,
    ):
        return "Error connecting to target"

    status_code = response.status_code
    headers = response.headers

    if status_code != 200:
        return f"Received non-200 status code: {status_code}"

    # Check for Server header
    if "Server" in headers:
        server_header = headers["Server"]
    else:
        server_header = "No Server header found"

    # Check for X-Powered-By header
    if "X-Powered-By" in headers:
        powered_by_header = headers["X-Powered-By"]
    else:
        powered_by_header = "No X-Powered-By header found"

    return {"server_header": server_header, "powered_by_header": powered_by_header}