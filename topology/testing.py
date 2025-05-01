import topology

def ping(client, server_ip, expected=True, count=1, timeout=1):
    """
    Ping from client to server_ip.
    expected: True if ping should succeed, False if it should fail.
    """
    # Add -W timeout to avoid blocking too long
    cmd = f"ping -c {count} -W {timeout} {server_ip} >/dev/null 2>&1; echo $?"
    ret_str = client.cmd(cmd).strip()
    try:
        ret = int(ret_str)
    except ValueError:
        # Treat parsing failure as ping failure
        ret = 1

    success = (ret == 0)
    if success == expected:
        return True  # Test passed
    else:
        print(f"Ping test FAILED: client={client.name}, target={server_ip}, expected={expected}, got={success}")
        return False

def curl(client, server, method="GET", payload="", port=80, expected=True):
    """
    Run curl to server.
    expected: True (expect 200/501), False (expect other codes)
    """
    if not isinstance(server, str):
        server_ip = str(server.IP())
    else:
        server_ip = server

    # Construct base curl command
    curl_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' -X {method}"

    # Special timeout for GET requests
    if method.upper() == "GET" or "TRACE":
        curl_cmd = f"curl --connect-timeout 3 --max-time 3 -s -o /dev/null -w '%{{http_code}}' -X {method}"

    if payload:
        payload = payload.replace("'", "'\"'\"'")
        curl_cmd += f" -d '{payload}'"

    cmd = f"{curl_cmd} http://{server_ip}:{port}"

    ret_code = client.cmd(cmd).strip()

    # Parse ret_code
    try:
        status = int(ret_code)
    except ValueError:
        status = 0  # Treat parse error as invalid

    success = (status in [200, 501, 403])

    if success == expected:
        return True
    else:
        print(f"Curl test FAILED: client={client.name}, target={server_ip}, method={method}, payload='{payload}', got HTTP {ret_code} (expected success={expected})")
        return False