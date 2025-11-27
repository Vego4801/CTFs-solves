import pwn
import re
import time

choosen_plaintext = b'A'*32		# one byte less for the block => 31
secret = 'CCIT{r3m3mb3r_th3_3cb_p3ngu1n?}'    # Already built because it takes too much

#pwn.context.log_level = 'debug'		# Uncomment to enable debugging
p = pwn.remote('padding.challs.cyberchallenge.it', 9030)


for plain_len in range(31, -1, -1):
	time.sleep(1)
	plaintext = choosen_plaintext[:plain_len]

	p.sendlineafter(b':', plaintext)
	ciphertext = re.match('(?:.*):\s*(.+)\n', p.recvlineS()).group(1)
	print(plaintext)

	for byte2try in range(256):

		# I dunno but it works!
		try_plaintext = plaintext[:plain_len] + secret.encode() + byte2try.to_bytes(1, 'big')

		p.sendlineafter(b':', try_plaintext)
		new_ciphertext = re.match('(?:.*):\s*(.+)\n', p.recvlineS()).group(1)

		print('TRYING:\t' + try_plaintext.decode('utf-8'))
		print('HAVE:\t' + ciphertext[32:64])
		print('GOT: \t' + new_ciphertext[32:64] + '\n')

		if new_ciphertext[32:64] == ciphertext[32:64]:
			secret += byte2try.to_bytes(1, 'big').decode()
			break

print(secret)
