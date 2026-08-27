#include <stdlib.h>
#include <stdio.h>

/*
 * This is a clean reconstruction of the small VM
 * used by the challenge binary to print data
 * (option 4; show_result function in the script)
 */
int main(void) {
	int8_t *program = station + 0xe0;
	uint8_t *data   = station + 0x60;

	size_t pc = 0;
	size_t out = 0;
	int off = 0;
	uint8_t acc = 0;

	while (pc < len) {
	    if (pc > 0x7f || out == 96)
	        break;

	    uint8_t op = program[pc];

	    if (op == 0xff)
	        break;

	    switch (op) {
		    case 0x43:              // 'C'
		        acc ^= data[off];
		        pc++;
		        break;

		    case 0x71:              // 'q'
		        printf("%02x", acc);
		        pc++;
		        out++;
		        break;

		    case 0x19: {            // change offset
		        int8_t delta = program[pc + 1];
		        pc += 2;

		        int new_off = off + delta;
		        if ((unsigned)(new_off + 0x60) <= 0xdf)
		            off = new_off;
		        break;
		    }

		    case 0x2d:              // '-'
		        printf("%02x", data[off]);
		        pc++;
		        out++;
		        break;

		    default:
		        goto done;
	    }
	}
}
