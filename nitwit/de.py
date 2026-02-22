import hashlib
import ast
from pwn import *

def get_hash(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def hash_chain(x: bytes, d: int) -> bytes:
    for _ in range(d):
        x = get_hash(x)
    return x

conn = remote('nitwit.challs.pwnoh.io', 1337, ssl=True)

print(conn.recvuntil(b"Public key: "))
pk_hex = conn.recvline().strip().decode()
print("PK:", pk_hex)

m_old = b'\x60' * 32
conn.recvuntil(b">>> ")
conn.sendline(m_old.hex().encode())

print(conn.recvuntil(b"Your signature is:\n"))
sig_line = conn.recvline().strip()
sig_old = ast.literal_eval(sig_line.decode())

admin_str = b"admin"
padding = b'\xff' * 27
m_new = admin_str + padding
assert len(m_new) == 32

forged_sig = list(sig_old)

differences = [0] * 66
differences[1] = 1
differences[3] = 4
differences[5] = 13
differences[7] = 9
differences[9] = 14

for i in range(10, 64):
    if i % 2 == 0:
        differences[i] = 9
    else:
        differences[i] = 15

differences[64] = 4
differences[65] = 12

for i in range(66):
    if differences[i] > 0:
        forged_sig[i] = hash_chain(sig_old[i], differences[i])

conn.recvuntil(b">>> ")
conn.sendline(m_new.hex().encode())

conn.recvuntil(b">>> ")
conn.sendline(repr(forged_sig).encode())

print(conn.recvline())
print(conn.recvline())
print(conn.recvline())
#bctf{i_f0rg0t_h0w_t0_r3ad_m4th_n0t4t10n}