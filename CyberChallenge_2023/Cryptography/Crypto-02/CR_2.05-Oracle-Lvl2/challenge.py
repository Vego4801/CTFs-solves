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


# Stesso concetto del livello precedente: questo perché se moltiplichiamo la flag (intero) per un numero,
# il risultato sarà sempre multiplo della flag stessa e quindi entra nell'if-statement che ritorna la flag
# decifrata (leakage; siccome è la prima entry che fallisce, ovvero la flag, ritorna quella)

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
      used.append(m)
      print('\nEncrypted: ' + str(encrypt(m)))

    # Decrypt
    elif choice == '2':
      c = int(input('\nCiphertext > ').strip())

      if c == flag_encrypted:
        print("Wait. That's illegal.")
      else:
        m = decrypt(c)

        for no in used:
          if m % no == 0:
            print("Wait. That's illegal.", no)
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
