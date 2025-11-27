from Crypto.Util.number import getStrongPrime, bytes_to_long
from secret import flag

p = getStrongPrime(1024)
n = p * p
ct = pow(bytes_to_long(flag), 65537, n)

print(f"N: {n}")
print("e: 65537")
print(f"Ciphertext: {ct}")
