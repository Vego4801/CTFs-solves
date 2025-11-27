from secret import flag, nbits
from Crypto.Util.number import getPrime, long_to_bytes
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

p = getPrime(nbits)
g = getPrime(nbits)

def gen_key():
    s = random.randint(0, nbits)
    return s, pow(g,s,p)

privA, pubA = gen_key()
privB, pubB = gen_key()

shared_secret = pow(pubA, privB, p)
key = hashlib.sha256(long_to_bytes(shared_secret)).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
ct = cipher.encrypt(pad(flag, 16)).hex()

print(f"p: {p}")
print(f"g: {g}")
print(f"pubA: {pubA}")
print(f"pubB: {pubB}")
print(f"Encrypted flag: {ct}")
