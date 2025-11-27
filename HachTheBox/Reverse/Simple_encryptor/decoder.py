from ctypes import CDLL


MAX_RAND = 32767

# Simula l'operazione assembly 'ROR' (ROtate Right)
ROR = lambda val, r_bits, max_bits: \
	((val & (2**max_bits - 1)) >> (r_bits % max_bits)) | \
	(val << (max_bits - (r_bits % max_bits)) & (2**max_bits - 1))


def read_data():
	with open('flag.enc', 'rb') as f:

		# Legge i secondi che serviranno per la decriptazione
		secs = f.read(4)
		
		# Legge la flag criptata
		flag = f.read()

	return secs, flag


def decode():
	# Usa la libreria di C ottenere il corretto risultato
	libc = CDLL("libc.so.6")

	flag = ''

	# Legge i dati che gli servono
	secs, encoded_flag = read_data()

	print(f"Decoding {encoded_flag}...")

	# Imposta il seed con i secondi presi dal file
	libc.srand(int.from_bytes(secs, 'little'))

	# Fa un "reverse" della funzione di criptazione del programma
	for byte in encoded_flag:
		print(hex(byte))

		# Reverse della seconda parte
		rnd2 = libc.rand() % MAX_RAND
		rnd2 = rnd2 & 0xFF	# Prende il primo byte del numero (meno significativo)
		rnd2 = rnd2 & 7
		byte = ROR(byte, rnd2, 0x8)

		# Reverse della prima parte
		rnd1 = libc.rand() % MAX_RAND
		rnd1 = rnd1 & 0xFF
		byte = byte ^ rnd1	# L'inverso dello XOR è lo XOR stesso!

		flag += chr(byte)

	print(f"Result: {flag}")


if __name__ == '__main__':
	decode()
