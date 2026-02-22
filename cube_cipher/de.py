from pwn import *

r = remote('cube-cipher.challs.pwnoh.io', 1337, ssl=True)
r.recvuntil(b'Option: ')
r.sendline(b'3')
hex_line = r.recvline().strip().decode()
r.recvuntil(b'Option: ')
S0 = hex_line
print(f"Initial: {S0}")

i = 0
while True:
    i += 1
    r.sendline(b'4')
    r.recvuntil(b'Option: ')
    r.sendline(b'3')
    hex_line = r.recvline().strip().decode()
    r.recvuntil(b'Option: ')
    print(f"After {i} scrambles: {hex_line}")
    if hex_line == S0:
        print(f"Order: {i}")
        break

for j in range(i-1):
    r.sendline(b'4')
    r.recvuntil(b'Option: ')

r.sendline(b'3')
flag_hex = r.recvline().strip().decode()
print(f"Flag hex: {flag_hex}")
flag = bytes.fromhex(flag_hex).decode('ascii')
print(f"Flag: {flag}")

r.close()
#bctf{the_cUb3_pl4yS_Y0U}