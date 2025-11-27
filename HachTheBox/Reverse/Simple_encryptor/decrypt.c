#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>


// NOTA: Utilizzerà 'uint8_t' che sta per il tipo 'unsigned 8-bit integer'
int main() {
	int size = 29;	// 32 - 4 = 28 + 1 = 29 per il '\n' alla fine della stringa
	FILE *fp;
	int seed;

	// Attenzione perché 'char' taglia il primo bit, invece 'uint8_t' no
	// NOTA: Provare a capire il perché
	uint8_t flag[size];

	// Apre il file criptato in modalità lettura a bytes
	fp = fopen("flag.enc", "rb");

	flag[28] = '\0';			// Rimpiazza il '\n' con il terminatore '\0'
	fread(&seed, 4, 1, fp);		// Legge il seed che sta nei primi 4 bytes del file 
	fread(&flag, 1, 28, fp);	// I rimanenti 28 bytes sono la flag criptata
	srand(seed);				// Imposta il seed con il valore letto dal file

	for(long i = 0; i < size-1; i++){
		uint8_t rand1 = rand();			// Primo valore random per invertire la prima fase della cifratura
		uint8_t rand2 = rand() & 7; 	// Secondo valore random per inverire la seconda fase della cifratura

		// Bisogna invertire prima la seconda fase e poi la prima, ovviamente
		uint8_t x = (flag[i] >> rand2) | (flag[i] << (8 - rand2));
		uint8_t c = x ^ rand1;		// ^ ===> XOR
		flag[i] = c;
    }

    printf("Decoded flag: %s\n", flag);
    fclose(fp);
}
