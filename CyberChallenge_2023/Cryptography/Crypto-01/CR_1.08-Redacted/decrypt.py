from Crypto.Cipher import AES
import binascii, string


# Obscured first block (C1): c5██████████████████████████d49e
# Visible first block (C1):	 c5dc598a00e6e31272bcb2ed502ad49e

def complete_key():
	ciphertext = bytes.fromhex("78c670cb67a9e5773d696dc96b78c4e0")
	key = "yn9RB3Lr43xJK2"     # Missing 2 bytes! (to bruteforce)

	# Bruteforce on last two bytes of key
	for second_last in string.ascii_letters + string.digits:
		for last in string.ascii_letters + string.digits:
			aes = AES.new((key + second_last + last).encode(), AES.MODE_ECB)     # ECB is fine since we want to encrypt block directly!

			# NOTE: In CBC, its blocks are the result of XOR-ing between previous cipher-block and actual plain-block
			# We just need the last block since it's result is what we are looking for
			block_cipher_enc = binascii.hexlify(aes.decrypt(ciphertext)).decode()

			# NOTE: These bytes used were found XOR-ing first byte and last two bytes of previous block
			if block_cipher_enc[:2] == 'b3' and block_cipher_enc[-4:] == 'b8fb':
				# print("Block matched:\t" + block_cipher_enc)
				# print("Key found:\t" + (key + second_last + last))
				return ((key + second_last + last), block_cipher_enc)


# Just use XOR properties :)
def find_block(block_cipher_enc: bytes, plaintext: bytes):
	C1 = bytes(a ^ b for (a, b) in zip(block_cipher_enc, plaintext))
	C1 = binascii.hexlify(C1).decode()
	return C1


plaintext = "AES with CBC is very unbreakable"
key, block_cipher_enc = complete_key()			# Completed key
C1 = find_block(bytes.fromhex(block_cipher_enc), plaintext[16:].encode('utf-8'))		# Previous block

# Finally we can retrieve the IV!
aes = AES.new(key.encode(), AES.MODE_ECB)
IV = find_block(aes.decrypt(bytes.fromhex(C1)), plaintext[:16].encode('utf-8'))
print(f"IV: {bytes.fromhex(IV).decode('utf-8')}")