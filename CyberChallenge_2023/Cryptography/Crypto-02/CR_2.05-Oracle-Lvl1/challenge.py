#!/usr/bin/env python3

import signal
from binascii import hexlify
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
from random import randint
from secret import FLAG
import string

TIMEOUT = 300 # 5 minutes time-out

def menu():
    print()
    print('Choice:')
    print('  [0] Exit')
    print('  [1] Encrypt')
    print('  [2] Decrypt')
    print('')
    return input('> ')

def encrypt(m):
    return pow(m, rsa.e, rsa.n)

def decrypt(c):
    return pow(c, rsa.d, rsa.n)


# D(C1 * C2, K) = D(C1, K) * D(C2, K) quindi basta encryptare un numero piccolo (es: 2) e moltiplicare l'hash con quello della flag.
# Dopodiché decriptare il risultato ottenuto dalla moltiplicazione e il plaintext ottenuto deve essere diviso per il numero precedentemente cifrato.
# Il risultato sarà un intero che deve essere convertito in stringa!

rsa = RSA.generate(1024)
flag_encrypted = pow(bytes_to_long(FLAG.encode()), rsa.e, rsa.n)
used = [bytes_to_long(FLAG.encode())]

def handle():
  print("================================================================================")
  print("=                      RSA Encryption & Decryption oracle                      =")
  print("=                                Find the flag!                                =")
  print("================================================================================")
  print("")
  print("Encrypted flag:", flag_encrypted)

  while True:
    choice = menu()

    # Exit
    if choice == '0':
      print("Goodbye!")
      break

    # Encrypt
    elif choice == '1':
      m = int(input('\nPlaintext > ').strip())
      print('\nEncrypted: ' + str(encrypt(m)))

    # Decrypt
    elif choice == '2':
      c = int(input('\nCiphertext > ').strip())

      if c == flag_encrypted:
        print("Wait. That's illegal.")
      else:
        m = decrypt(c)
        print('\nDecrypted: ' + str(m))

    # Invalid
    else:
      print('bye!')
      break

if __name__ == "__main__":
    signal.alarm(TIMEOUT)
    handle()
