#!/usr/bin/env python3

from pwn import *

exe = ELF('./solve')

context.binary = exe


def conn():
    global solver, r

    solver, r = process([exe.path]), remote("ezvm.challs.cyberchallenge.it", 9241)

    return solver, r



def main():
    solver, r = conn();

    key = solver.recv(24)    

    r.sendlineafter(b'Login key: ', key)

    flag = r.recvlinesS(5)[-1]
    log.warn(f'Flag obtained: {flag}')


if __name__ == "__main__":
    main()
