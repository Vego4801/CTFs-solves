from pwn import *
from time import sleep
from math import gcd


url = 'oracle.challs.cyberchallenge.it'
port = 9043

# context.log_level = 'debug'
conn = remote(url, port)


e = 65537
x = 11		# Primo numero per il recupero di N
y = 7		# Secondo numero per il recupero di N
z = 2		# Costante da invertire e cifrare per bypassare i controlli


ct_flag = int(conn.readlinesS(6)[-1][16:])

# Manda il primo numero
conn.sendlineafter(b'> ', '1')
conn.sendlineafter(b'> ', str(x))
x_c = int(conn.recvlinesS(2)[-1][11:])	# "Encrypted: " = 11 chars

sleep(1)

# Manda il secondo numero
conn.sendlineafter(b'> ', '1')
conn.sendlineafter(b'> ', str(y))
y_c = int(conn.recvlinesS(2)[-1][11:])	# "Encrypted: " = 11 chars

sleep(1)

# Recupera N con i ciphertext ottenuti dai due numeri
x_e, y_e = (x ** 65537), (y ** 65537)
N = gcd((x_e - x_c), (y_e - y_c))

# Siccome rimane un piccolo multiplo condiviso tra i due numeri, 
# conviene filtrare i numeri più piccoli e toglierli per ottenere l'effettivo N
# Per pigrizia non l'ho fatto, ma sarebbe da generare i primi 1000 - 10000 numeri primi
# e, se il modulo con N è 0, dividerli a N e continuare così per tutti quei numeri

# NOTA: D(a / b) = D(a * 1/b)
# Calcoliamo una frazione da moltiplicare al ciphertext della flag.
# Ci serve calcolare, però, l'inverso del numero (ovvero se vogliamo, per esempio,
# usare 1/2 come costante, dobbiamo calcolare l'inverso di 2^e mod N

c = pow(pow(z, e, N), -1, N)
ct = (c * ct_flag) % N

conn.sendlineafter(b'> ', '2')
conn.sendlineafter(b'> ', str(ct))

pt_flag = int(conn.recvlinesS(2)[-1][11:])	# "Encrypted: " = 11 chars
pt_flag = (pt_flag * z) % N

print(pt_flag.to_bytes(32, 'big').decode('ascii'))

conn.close()

