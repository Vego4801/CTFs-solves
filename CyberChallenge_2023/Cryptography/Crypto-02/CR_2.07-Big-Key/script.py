from discrete_log import pohlig_hellman
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes


# SPIEGAZIONE:
# Per trovare il fattore privato di B o di A, nel caso siano numeri molto grandi
# è molto più veloce calcolare il logaritmo discreto.
# Tra i vari algoritmi per risolvere il DLP (Discrete Logarithm Problem), quello
# di Pohlig-Hellman è uno dei più veloci, con una complessità di O(e * sqrt(p))
# per gruppi ciclici G dell'ordine n = p^e

# https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm
# https://github.com/bobmitch23/discrete-log


with open('./output.txt', 'r') as f:
	p = int(f.readline()[3:])
	g = int(f.readline()[3:])
	pubA = int(f.readline()[6:])
	pubB = int(f.readline()[6:])
	ct_flag = bytes.fromhex(f.readline()[16:])


privB = pohlig_hellman.solve(g, pubB, p).solution
print(f'Found B secret key!')
print(f'B\'s Secret Key: {privB}')

shared_secret = pow(pubA, privB, p)
key = sha256(long_to_bytes(shared_secret)).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
pt = cipher.decrypt(ct_flag).decode('ascii')

print(f'\nFLAG: {pt}')

