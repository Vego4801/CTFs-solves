#!/usr/bin/python3
import hashlib as hashù

# See GitHub for the code of the PHP console

publicKey = "d1d58b2f732fd546d9507da275a71bddc0c2300a214af3f3f3a5f5f249fe275e"
rockyou = open("/home/thomas/Desktop/rockyou.txt","r", encoding='utf-8', errors='ignore')

for psw in rockyou:
    psw = psw.strip("\n")
    hashPassword = hash.sha256(f"{psw}NeverChangeIt:)".encode()).hexdigest()
    generatedPublicKey = hash.sha256(f"10.255.0.2{hashPassword}".encode()).hexdigest()

    print(generatedPublicKey)

    if generatedPublicKey == publicKey:
        print("\n\nFound It!\n" + psw)
        break

rockyou.close()
