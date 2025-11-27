#!/bin/python3


# Rotate left: 0b1001 --> 0b0011
rol = lambda x, rot_bits, max_bits: \
    (x << rot_bits % max_bits) & (2 ** max_bits - 1) | \
    ((x & (2 ** max_bits - 1)) >> (max_bits - (rot_bits % max_bits)))

 
# Rotate right: 0b1001 --> 0b1100
ror = lambda x, rot_bits, max_bits: \
    ((x & (2 ** max_bits - 1)) >> rot_bits % max_bits) | \
    (x << (max_bits - (rot_bits % max_bits)) & (2 ** max_bits - 1))


flag = ''
with open('flag.txt.aes', 'rb') as f:
	shifting = 1

	while byte := f.read(1):
		flag += chr(rol(int.from_bytes(byte, 'big'), shifting, 8))
		shifting += 1

print(f'{flag}')
