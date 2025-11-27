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

  for _ in range(5):
    choice = menu()

    # Exit
    if choice == '0':
      print("Goodbye!")
      break

    # Encrypt
    elif choice == '1':
      m = int(input('\nPlaintext > ').strip())
      used.append(m)
      print('\nEncrypted: ' + str(encrypt(m)))

    # Decrypt
    elif choice == '2':
      c = int(input('\nCiphertext > ').strip())

      if c == flag_encrypted:
        print("Wait. That's illegal.")
      else:
        m = decrypt(c)

        if any([m % no == 0 for no in used]):
          print("Wait. That's illegal.")
          break
        else:
          print('\nDecrypted: ' + str(m))

    # Invalid
    else:
      print('bye!')
      break

if __name__ == "__main__":
    signal.alarm(TIMEOUT)
    handle()
