import pwn
import re

# NOTA: È stata scritta la write-up di questa challenge perché, pur non essendo difficile
# come challenge, aiuta comunque nello scripting e a relazionare strumenti come PwnTools
# e le RegExps per ottenere il risultato che cerchiamo; l'intero script e i suoi commenti
# vengono considerati come l'intera write-up!

# SPIEGAZIONE:
# La challenge consiste nel rispondere a dei quesiti, inviando le risposte in bytes.
# Possiamo automatizzare il tutto leggendo le domande e parsando i dati che ci servono per
# costruire la risposta.


# pwn.context.log_level = 'debug'
conn = pwn.remote('piecewise.challs.cyberchallenge.it', '9110')
flag = ''

while not flag.endswith('}'):
	question = conn.readlineS()

	if 'empty line' in question:
		conn.send(b'\n')

	elif 'the number' in question:
		match = re.match(r".*?number (-\d+|\d+).*?(\d+)-bit.*?(\w+)-endian.*", question).groups()

		n = int(match[0])
		b = int(match[1]) // 8
		f = match[2]

		conn.send(n.to_bytes(b, byteorder = f))

	else:
		# print(question)
		raise Exception("Question not covered!")


	flag = re.match(r".*: (.+)", conn.readlineS()).group(1)
	print(f"{flag}", end = '\r')
	
print(f"{flag}")
conn.close()
