#include <iostream>
#include <string.h>

using namespace std;


uint8_t memory[256] = {0};



void init_memory() {
	for (size_t i = 0; i < 0x18; ++ i) {
		memory[i] = 0x40;
	}

	memory[0x04] = 0x2d;
	memory[0x09] = 0x2d;
	memory[0x0e] = 0x2d;
	memory[0x13] = 0x2d;

	memory[0xfe] = 0x0f;
	memory[0xff] = 0xf0;
}



bool check_segment(size_t start, size_t end, uint8_t cc, uint8_t cd) {
	memory[0xcc] = cc;
	memory[0xce] = 0x00;

	memory[0xcd] = memory[start] & memory[0xfe];
	memory[0xcd] = memory[0xcd] | memory[0xff];

	for (size_t i = start + 1; i < end; ++ i) {
		memory[0xcd] = ~memory[0xcd];
		memory[0xce] = memory[0xcd] + memory[0xce];
		memory[0xcd] = memory[i] & memory[0xfe];
		memory[0xcd] = memory[0xcd] | memory[0xff];
	}

	memory[0xcd] = ~memory[0xcd];
	memory[0xce] = memory[0xcd] + memory[0xce];

	memory[0xcd] = cd;

	memory[0xce] = memory[0xce] - memory[0xcd];
	memory[0xcc] = memory[0xce] ^ memory[0xcc];

	return memory[0xcc] == memory[0xd0];
}



int main(int argc, char const *argv[]) {
	init_memory();

	for (int segment = 0; segment < 5; ++ segment) {
		bool found = false;
		size_t start = segment * 5;
		size_t end = start + 4;
		uint8_t cc = 0, cd = 0;

		switch (segment) {
			case 0:
				cc = 0x27;
				cd = 0xf3;
				break;

			case 1:
				cc = 0x37;
				cd = 0xcd;
				break;

			case 2:
				cc = 0x14;
				cd = 0x1a;
				break;

			case 3:
				cc = 0xaf;
				cd = 0x66;
				break;

			case 4:
				cc = 0xba;
				cd = 0x4d;
				break;
		}


		for (size_t a = 0; a < 0x0f and !found; ++ a) {
			memory[start + 3] = 0x40 + a;

			for (size_t b = 0; b < 0x0f and !found; ++ b) {
				memory[start + 2] = 0x40 + b;

				for (size_t c = 0; c < 0x0f and !found; ++ c) {
					memory[start + 1] = 0x40 + c;

					for (size_t d = 0; d < 0x0f and !found; ++ d) {
						memory[start] = 0x40 + d;

						found = check_segment(start, end, cc, cd);
					}
				}
			}
		}
	}

	for (size_t i = 0; i < 0x18; ++ i) {
		cout << ((char) memory[i]);
	}

	return 0;
}