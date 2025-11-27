import pwn
import time


# pwn.context.log_level = 'debug'
conn = pwn.remote("padding.challs.cyberchallenge.it", "9033")
BLOCK_SIZE = 16


enc = conn.recvlinesS(2)[1]
IV = enc[:32]
FLAG = enc[32:]


def oracle(data: str) -> bool:
	conn.sendlineafter(b'? ', bytes(data, 'utf-8'))
	resp = conn.recvlineS()

	if resp.lower().find('padding is incorrect') != -1:
		return False
	else:
		return True


def decrypt_block(block: str, iv: str) -> bytes:
	print("Decrypting block " + block + " ...\n")

	# Starts out nulled then each iteration of the main loop will add one byte to it.
	# At the end it will contain the block intermediate decryption
	# NOTE: Needs to be nulled at the beginning otherwise the first operation of XORing
	# inside the loop will fail! (Null byte XOR anything will return the same byte)
	dec = ['00'] * BLOCK_SIZE

	for pad_val in range(1, BLOCK_SIZE + 1):

		# Each iteration the "IV" needs to be updated by XORing with new padding value so the
		# padding value in the resulting plaintext will be increased by one.
		# NOTE: This is useless for the first iteration since the last byte will be bruteforced
		iv = bytes([pad_val ^ byte for byte in bytes.fromhex(''.join(map(str, dec)))]).hex()

		# Bruteforce until a good byte is found
		for byte in range(256):
			iv = iv[: (BLOCK_SIZE * 2) - (pad_val * 2)] + byte.to_bytes(1, 'big').hex() + iv[(BLOCK_SIZE * 2) - (pad_val * 2) + 2:]
			data = iv + block
			print(f"[+] Trying [{byte:03} / 256];\t IV = {iv}", end = '\r')

			if oracle(data):
				dec[-pad_val] = (pad_val ^ bytes.fromhex(iv)[-pad_val]).to_bytes(1, 'big').hex()

				print("\x1b[2K\033[1A")		# Clear line + Move cursor up
				print(f"[!] Candidate found: 0x{byte.to_bytes(1, 'big').hex()}")
				print( "[-] Intermediate decryption: ", dec, "\n")
				break

	return bytes.fromhex(''.join(dec))


def main():
	blocks = [FLAG[i : i + (BLOCK_SIZE * 2)] for i in range(0, len(FLAG), BLOCK_SIZE * 2)]
	result = ''

	# Since we can pass IV and an arbitrary long ciphertext, we can reduce the multi-block
	# CBC decryption problem in single-block CBC decryption subproblems by using previous
	# blocks as IVs and target block as the single block to decrypt! (not the only way but
	# the easier i guess)

	iv = IV
	for block in blocks:
		dec = decrypt_block(block, iv)      # This is our D(C_i, K)
		
		# Retrieve plaintext: P_i = D(C_i, K) ^ C_i-1 (at the beginning, C_i-1 = IV)
		plaintext = str(chr(iv_byte ^ dec_byte) for iv_byte, dec_byte in zip(bytes.fromhex(iv), dec))
		result += plaintext
		iv = block
		break

	print("Plaintext found: " + result)
	conn.close()


if __name__ == '__main__':
	main()
