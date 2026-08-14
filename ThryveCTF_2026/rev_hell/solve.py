#!/usr/bin/env python3

TARGET = [
    0x67, 0xf8, 0x71, 0xec,
    0x32, 0x37, 0x3a, 0xb7,
    0x70, 0x19, 0x47, 0xf6
]

def solve():
    # This is basically 3*x == y (mod 256)
    inv3 = pow(3, -1, 256)

    solves = []

    # We now pick x[0] and x[1] and derive the other x'es
    for x0 in range(256):
        for x1 in range(256):
            x = [0] * 12
            x[0] = x0
            x[1] = x1

            # The equation should be something like:
            #  3 * (x[i+2] + (x[i+1] ^ x[i])) == TARGET[i] (mod 256) 
            # 
            # So our x[i+2] is = TARGET[i] / 3 - (x[i+1] ^ x[i]) (mod 256)
            for i in range(10):
                value = (TARGET[i] * inv3) & 0xff
                x[i + 2] = (value - (x[i + 1] ^ x[i])) & 0xff

            is_ok = True

            for i in range(12):
                lhs = (3 * (x[(i + 2) % 12] + (x[(i + 1) % 12] ^ x[i]))) & 0xff

                if lhs != TARGET[i]:
                    is_ok = False
                    break

            if is_ok:
                solves.append(bytes(x))

    return solves


if __name__ == "__main__":
    solves = solve()

    print(f"Found {len(solves)} solution(s):")

    # Somewhere here there's the real flag
    for s in solves:
        print(f"Thryve{{{s.decode(errors='ignore')}}}")
