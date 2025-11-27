import re
import string


f = open("./challenge.txt", "r")
content = f.readlines()

N = int(re.match(r'n = (\d+)', content[0]).group(1))
E = int(re.match(r'e = (\d+)', content[1]).group(1))
C = re.match(r'c = \[((?:\d+,)*\d+)\]', content[2]).group(1).split(',')

alphabet = {}
for c in string.ascii_letters + string.digits + string.punctuation:
    m = int.from_bytes(bytes(c, 'ascii'), byteorder='big')
    enc = (m ** E) % N
    alphabet[enc] = c

pt = ''
for ct in C:
    pt += alphabet[int(ct)]

print(pt)
