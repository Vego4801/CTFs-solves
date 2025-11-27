# EzVM manual

Quick and ez guide to the EzVM and its instruction set.

EzVM was created to easily check keys! Since its purpose is only to check the validity of a given input, the only instruction that alters the behavior of the EzVM is the `chk` instruction, which simply terminates the execution if the check does not pass. No other instruction exists to alter the control-flow, and no instruction exists to produce any output.

## Basics

 - The EzVM only has 10 different instructions of different fixed length.

 - The EzVM only works with **unsigned one byte integer values**. Operations performing over/underflow do not have any side effect. The only value which has no bounds is the program counter: a program can have any length.

 - The EzVM has **no registers**! That's right, everything is done directly on memory, and since all values handled by the EzVM are unsigned bytes, the memory only consists of 256 bytes, which are always initialized to `0` before starting any program.

 - If the exit code of the EzVM after executing a program is 0, then the input was correct. This allows for fast and easy input checking operations! ;)

Possible exit codes of the EzVM when executing a program are:

 - 0: the program was correctly executed until its end (== correct input).
 - 1: some check did not pass (== incorrect input).
 - 2: invalid/illegal instruction encountered.
 - 3: program does not exist or is not accessible.

---

## Instruction reference

### NOP

No-op instruction, does nothing.

	Assembly..........: nop
	Machine code (hex): 00

### IN

Gets X bytes from standard input and stores them in memory starting at address Y.

	Assembly..........: in X Y
	Machine code (hex): 01 XX YY

### STO

Stores the byte X at address Y in memory.

	Assembly..........: sto X Y
	Machine code (hex): 02 XX YY

### ADD

Adds the two bytes at addresses X and Y and stores the result at address Z.

	Assembly..........: add X Y Z
	Machine code (hex): 03 XX YY ZZ

### SUB

Subtracts the byte at address Y from the byte ad address X and stores the result at address Z.

	Assembly..........: sub X Y Z
	Machine code (hex): 04 XX YY ZZ

### NOT

Performs the bitwise negation of the byte at address X.

	Assembly..........: not X
	Machine code (hex): 05 XX

### AND

Performs the bitwise AND of the two bytes at addresses X and Y and stores the result at address Z.

	Assembly..........: and X Y Z
	Machine code (hex): 06 XX YY ZZ

### OR

Performs the bitwise OR of the two bytes at addresses X and Y and stores the result at address Z.

	Assembly..........: or X Y Z
	Machine code (hex): 07 XX YY ZZ

### XOR

Performs the bitwise XOR of the two bytes at addresses X and Y and stores the result at address Z.

	Assembly..........: xor X Y Z
	Machine code (hex): 08 XX YY ZZ

### CHK

Compares the bytes at addresses X and Y in memory, halting the execution if they are different.

	Assembly..........: chk X Y
	Machine code (hex): 09 XX YY
