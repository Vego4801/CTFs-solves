#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>


int main() {
	// int64_t x = 18446744073709551617 * (64 >> 3);
	int64_t x = 2305843009213693953 * (64 >> 3);

	printf("Size of int: %d\n", sizeof(x));
	printf("x: %" PRIu64 "\n", x);
	// printf("x: %u\n", x);

	char* ptr = malloc(x);

	if (ptr == NULL) {
		printf("This is bad!\n");
	} else {
		memset(ptr, 65, 1);
		printf("This is good!\n");
		printf("%c\n", *ptr);
	}

    return 0;
}

