from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from hashlib import sha256


# SPIEGAZIONE:
# Come suggerisce la chellenge, proviamo a fare bruteforce sulla chiave privata di B
# per ottenere lo shared_secret e poter decifrare la flag


with open('./output.txt', 'r') as f:
	p = int(f.readline()[3:])
	g = int(f.readline()[3:])
	pubA = int(f.readline()[6:])
	pubB = int(f.readline()[6:])
	ct_flag = bytes.fromhex(f.readline()[16:])


# Bruteforce is the way (weird, i know)
privB = 0		# g^b mod p
while True:
	print(f'Attempt: {privB}', end = '\r')

	calculated_pubB = pow(g, privB, p)
	if calculated_pubB == pubB:
		print(f'Found B secret key!')
		print(f'B\'s Secret Key: {privB}')
		
		shared_secret = pow(pubA, privB, p)

		key = sha256(long_to_bytes(shared_secret)).digest()[:16]
		cipher = AES.new(key, AES.MODE_ECB)
		pt = cipher.decrypt(ct_flag).decode('ascii')

		print(f'\nFLAG: {pt}')
		break

	privB += 1
