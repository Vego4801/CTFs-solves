#!/usr/bin/python3
import hashlib
import urllib
import requests
import re


# Richiesta pagina e ricerca della stringa
req = requests.session()        # <-- Crea una sessione per la persistenza dei dati
resp = req.get("http://docker.hackthebox.eu:30278/")
string = re.search(r"<h3 align='center'>(\w+)</h3>", resp.text)     # <-- Ricerca la stringa del sito ("\w" sta per "prendi qualsiasi parola" [compreso '_']
                                                                    # Vedere meglio "+", non andava senza)
print(resp.text)


# Elaborazione della stringa in un hash secondo MD5
result = hashlib.md5(string.group(1).encode('utf-8')).hexdigest()   # <-- .group(0) prende tutta la stringa (<h3 ... </h3>) mentre .group(n) 
                                                                    # prende il sottogruppo N, quello scritto (\w*) (ovvero la stringa)

# Creazione Payload per la request
payload = { 'hash': result }
#params_encoded = urlencode(payload, quote_via=quote_plus)
print("\nSending this payload --> " + str(payload))


# Creazione richiesta e recupero risposta dal sito web
resp = req.post(url = "http://docker.hackthebox.eu:30278/", data = payload)


# Visualizzazione leggibile della risposta 
print(resp.text)



# https://realpython.com/python-requests/#the-get-request
# https://docs.python.org/2/library/re.html#re.MatchObject.group
