import gmpy2
from Crypto.Util.number import long_to_bytes


with open('./output.txt', 'r') as f:
	N = int(f.readline()[3:])
	e = int(f.readline()[3:])
	ct = int(f.readline()[12:])


# SPEIGAZIONE: Siccome N = p * p, phi(N) = p * (p - 1), quindi abbiamo tutto
# quello che ci serve per ottenere gli altri valori e decifrare la flag!
p = gmpy2.isqrt(gmpy2.mpz(N))
phi = p * (p - 1)
d = pow(e, -1, phi)

pt = pow(ct, d, N)
pt = long_to_bytes(pt).decode('ascii')

print(f'FLAG: {pt}')
