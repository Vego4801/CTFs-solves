#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BUFSIZE 100


long increment(long in) {
	return in + 1;
}

long get_random() {
	return rand() % BUFSIZE;
}

int main() {
	long ans = get_random();
	ans = increment(ans);

	printf("Number: %ld\n", ans);

	ans = get_random();
	ans = increment(ans);

	printf("Number: %ld\n", ans);
	return 0;
}