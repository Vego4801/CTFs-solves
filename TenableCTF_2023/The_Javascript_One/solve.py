import base64

enc_flag = base64.b64decode('Zm1jZH92N2tkcFVhbXs6fHNjI2NgaA==')
flag = ''

for i in range(len(enc_flag)):
	flag += chr(enc_flag[i] ^ i)	# XOR

print(f"The flag is: {flag}")
