#!/usr/bin/env python3

from pwn import *
import re

exe = ELF("./exceptional-checking_patched")     # Patched SIGTRAP with SIGINT so it does not crash (for some reason it does)
context.binary = exe

hidden_func_instruction = []


def conn():
    return process(["gdb", exe.path])


def remove_color_codes(text: str):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)


def main():
    r = conn()

    # Add breakpoints to the desired points
    r.sendlineafter(b'pwndbg>', b'break *0x401341')     # call rdx (check_number)
    r.sendlineafter(b'pwndbg>', b'break *0x401196')     # Start of the signal_handler

    # Define a useful function
    r.sendlineafter(b'pwndbg>', b'define call_handler')
    r.sendlineafter(b'>', b'ni')
    r.sendlineafter(b'>', b'signal 2')
    r.sendlineafter(b'>', b'end')

    # Run and send the code (the code isn't necessary as we just want to retrieve the hidden function)
    r.sendlineafter(b'pwndbg>', b'r')
    r.sendline(b'A' * 16)

    # Get in the function
    r.sendlineafter(b'pwndbg>', b'si')

    # Call signal_handler and exit (first time)
    r.sendlineafter(b'pwndbg>', b'ni')
    r.sendlineafter(b'pwndbg>', b'call_handler')
    r.sendlineafter(b'pwndbg>', b'finish')
    r.sendlineafter(b'pwndbg>', b'finish')

    # Get the instruction
    r.sendlineafter(b'pwndbg>', b'x/i $rip')
    hidden_func_instruction.append( remove_color_codes(r.recvlineS()) )        # Remove the goddamn colors

    # Iterate to get all the lines (the number of calls was observed with "strace")
    for _ in range(100):
        r.sendlineafter(b'pwndbg>', b'ni 2')
        r.sendlineafter(b'pwndbg>', b'call_handler')
        r.sendlineafter(b'pwndbg>', b'finish')
        r.sendlineafter(b'pwndbg>', b'finish')

        r.sendlineafter(b'pwndbg>', b'x/i $rip')
        hidden_func_instruction.append( remove_color_codes(r.recvlineS()) )        # Remove the goddamn colors

    # Write the instruction to a file
    # NOTE: "rdi" register contains the address to the input string
    with open("./hidden_function.txt", "w") as file:
        for instruction in hidden_func_instruction:
            file.write(instruction[3:])


# NOTE: From now on we can simply see "mov dl,0xYY" instruction for the corrisponding "xor dl,BYTE PTR [rdi+0xZZ]" instruction
# Flag: CCIT{tr4p_0r1en73d_pr0gr4mm1ng}
if __name__ == "__main__":
    main()
