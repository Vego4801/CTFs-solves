#!/usr/bin/env python3

from pwn import *
import re

exe = ELF("./broke_patched")
solver = ELF("./solver")
libc = ELF("./libc6.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("broke.challs.cyberchallenge.it", 37001)

    return r



def main():
    solver_exe = process([solver.path])
    output = solver_exe.recvlines(4)

    match = re.match(rb'License ID: \t(\d+)', output[0])
    licence_id = match.group(1)

    match = re.match(rb'Account ID: \t(\d+)', output[1])
    account_id = match.group(1)

    match = re.match(rb'License Key: \t(.{32})', output[2])
    licence_key = match.group(1)

    log.info(f'License ID: {licence_id}')
    log.info(f'Account ID: {account_id}')
    log.info(f'License Key: {licence_key}')

    r = conn()

    #r.sendlineafter(b'License ID: ', licence_id)
    #r.sendlineafter(b'License Account ID: ', account_id)
    r.sendlineafter(b'License key: ', licence_key)

    flag = r.recvlinesS(2)[-1]
    log.warn(f'Flag obtained: {flag}')


if __name__ == "__main__":
    main()


'''

   0x555555555274:  lea    ebx,[rip+0x3da6]        # 0x555555559020
   0x55555555527a:  mov    ebp,0x0
   0x55555555527f:  mov    r14,rbx
   0x555555555282:  movzx  r13d,BYTE PTR [rbx]
   0x555555555286:  lea    rax,[rip+0x3d93]        # 0x555555559020
   0x55555555528d:  mov    QWORD PTR [rsp+0x8],rax
   0x555555555292:  mov    eax,ebx
   0x555555555294:  sub    eax,DWORD PTR [rsp+0x8]
   0x555555555298:  and    eax,0x3f
   0x55555555529b:  lea    rcx,[rip+0xdfe]        # 0x5555555560a0
   0x5555555552a2:  mov    edx,r13d
   0x5555555552a5:  add    dl,BYTE PTR [rcx+rax*1]
   0x5555555552a8:  mov    eax,edx
   0x5555555552aa:  add    ebp,eax
   0x5555555552ac:  call   0x555555555229
   0x5555555552b1:  test   al,al
   0x5555555552b3:  je     0x5555555552ed
   0x5555555552b5:  call   0x555555555229
   0x5555555552ba:  test   al,al
   0x5555555552bc:  je     0x5555555552ed
   0x5555555552be:  movzx  r12d,bpl
   0x5555555552c2:  movzx  eax,bpl
   0x5555555552c6:  movzx  eax,BYTE PTR [r14+rax*1]
   0x5555555552cb:  mov    BYTE PTR [rbx],al
   0x5555555552cd:  call   0x555555555229
   0x5555555552d2:  test   al,al
   0x5555555552d4:  je     0x5555555552ed
   0x5555555552d6:  movsxd r12,r12d
   0x5555555552d9:  mov    BYTE PTR [r14+r12*1],r13b
   0x5555555552dd:  add    rbx,0x1
   0x5555555552e1:  lea    rax,[rip+0x3e38]        # 0x555555559120
   0x5555555552e8:  cmp    rbx,rax
   0x5555555552eb:  jne    0x555555555282
   0x5555555552ed:  add    rsp,0x18
   0x5555555552f1:  pop    rbx
   0x5555555552f2:  pop    rbp
   0x5555555552f3:  pop    r12
   0x5555555552f5:  pop    r13
   0x5555555552f7:  pop    r14
   0x5555555552f9:  pop    r15
   0x5555555552fb:  ret

'''