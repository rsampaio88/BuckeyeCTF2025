# NITWIT

**Category:** Crypto  
**CTF:** BuckeyeCTF

---

## Challenge Overview

**Objective:**

- Obtain a valid signature for a message containing "admin"
- The server signs one message of our choice (but it cannot contain "admin")
- Each connection provides the public key
- We must forge a signature for a message containing "admin"

---

## Given Script

```python
import hashlib
import random
import ast
from math import log
from flag import flag

"""
This implements Winternitz one-time signatures as defined in http://toc.cryptobook.us
"""

# Define Winternitz parameters

v = 256  # maximum bits for message size
hash_size = 32
d = 15  # base

n_0 = 64
assert (d + 1) ** n_0 == 2**v

n_1 = int(log(n_0, d + 1)) + 1
n = n_0 + n_1


def get_hash(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


def hash_chain(x: bytes, d: int) -> bytes:
    for _ in range(d):
        x = get_hash(x)
    return x


def int_to_vec(m: int, vec_len: int, base: int) -> list[int]:
    # Given an integer, output a vector that represents the digits of m in the
    # specified base (big-endian)
    digits = [0] * vec_len
    i = len(digits) - 1
    while m > 0:
        digits[i] = m % base
        m //= base
        i -= 1
    return digits


def domination_free_function(m: int) -> list[int]:
    # This function maps an integer to a vector.
    # What is a domination free function?
    # Let f(a) = xs
    # Let f(b) = ys
    # If f is a domination free function, then
    # all(x[i] >= y[i] for i in range(len(xs)))
    # must be false for any integers a and b.

    m_vec = int_to_vec(m, n_0, d + 1)

    # Compute checksum
    c = (d * n_0) - sum(m_vec)
    c_vec = int_to_vec(c, n_1, d + 1)

    return m_vec + c_vec


class Winternitz:
    def __init__(self):
        # Secret key stuff
        self.secret = random.SystemRandom().getrandbits(v)
        prg = random.Random(self.secret)
        self.xs = [prg.randbytes(hash_size) for _ in range(n)]

        # Public key stuff
        self.ys = [hash_chain(x, d) for x in self.xs]

    def public_key(self) -> bytes:
        return get_hash(b"".join(self.ys))

    def sign(self, m: bytes) -> list[bytes]:
        if len(m) * 8 > v:
            raise ValueError("Message too long")

        ss = domination_free_function(int.from_bytes(m, "big"))
        return [hash_chain(self.xs[i], s) for i, s in enumerate(ss)]

    def verify(self, public_key: bytes, m: bytes, signature: list[bytes]):
        ss = domination_free_function(int.from_bytes(m, "big"))
        ys = [hash_chain(signature[i], d - s) for i, s in enumerate(ss)]
        return public_key == get_hash(b"".join(ys))


def main():
    print("Welcome to my signing service!")

    w = Winternitz()
    pk = w.public_key()
    print(f"Public key: {pk.hex()}")

    print("Enter a message to sign as hex string:")
    m = bytes.fromhex(input(">>> "))
    if b"admin" in m:
        print("Not authorized")
        return

    sig = w.sign(m)
    print(f"Your signature is:")
    print(sig)

    print()
    print("Can you forge a signature for another message?")

    print("Enter a new message to sign as a hex string:")
    m_new = bytes.fromhex(input(">>> "))
    if m == m_new:
        print("Repeated message")
        return

    print("Enter signature:")
    forged_sig = ast.literal_eval(input(">>> "))
    print(forged_sig)
    if type(forged_sig) is not list:
        print("Bad signature")
        return
    if len(forged_sig) != n:
        print("Bad signature")
        return
    if not all(type(x) is bytes for x in forged_sig):
        print("Bad signature")
        return
    if not all(len(x) == hash_size for x in forged_sig):
        print("Bad signature")
        return

    if w.verify(pk, m_new, forged_sig):
        if b"admin" in m_new:
            print("You must be the admin, so here's your flag:")
            print(flag)
        else:
            print("Valid signature, but you're not admin")
    else:
        print("Signature failed to verify")


if __name__ == "__main__":
    main()
```

---

## Script Explanation

### Key Generation

- **xs** = [x_1, x_2, ..., x_n] where each x_i is random with 32 bytes (private key)
- **ys** = [ys_1, ys_2, ..., ys_n] where ys_i = hash_chain(x_i, d) for each i
- (hash_chain applies the hash function d times: H(H(...H(x_i)...)))
- **pk** = H(ys_1 + ys_2 + ... + ys_n) (public key, provided to us - concatenated)

### Signature Process

The server asks for a message in hex to sign (cannot contain "admin"):

1. **m** (message) → m_int (integer) → m in base 16 → m_v (vector)
2. Calculate checksum: **c** = 15 × 64 - sum(m_v)
3. Convert checksum to base 16: **c_v** = [c₁, c₂]
4. Combine: **ss** = m_v + c_v = [m₁, m₂, ..., m₆₄, c₁, c₂]
5. Generate signature: **sig** = [H^(ss[i])(x_i) for i = 0, ..., n-1]

### Verification Process

Given pk, m_new, and forged_sig:

1. Convert m_new to base 16 vector: m_new_v
2. Calculate checksum: c_new = 15 × 64 - sum(m_new_v)
3. Convert to base 16: c_v = [c_new,1, c_new,2]
4. Combine: ss_new = [m_new,1, m_new,2, ..., m_new,64, c_new,1, c_new,2]
5. **Verify:** H^(d - ss_new_i)(forged_i) = ys_i for all i

If verification succeeds and "admin" is in m_new, we get the flag.

---

## Exploit Technique

### The Problem

We can't sign an "admin" message initially, so we need to forge one.

### Breaking Down "admin"

```
admin = ['a',  'd',  'm',  'i',  'n']
      = [97,   100,  109,  105,  110] (decimal)
      = [[6,1], [6,4], [6,13], [6,9], [6,14]] (base 16)
```

This gives us the vector: **[6, 1, 6, 4, 6, 13, 6, 9, 6, 14, ...]** (+ 27 more elements for padding)

### Key Insight

We can decompose the admin vector:

```
[6, 1, 6, 4, 6, 13, 6, 9, 6, 14] =
[6, 0, 6, 0, 6, 0, 6, 0, 6, 0] + [0, 1, 0, 4, 0, 13, 0, 9, 0, 14]
```

Since we **can't reverse hashes** but we **can hash forward**, we need to use the signature from our first message to forge the admin signature.

### The Attack Strategy

From the verification equation:

```
H^(d - ss_new[i]) = H^d(x[i])
```

If we choose `forge[i] = H^(ss_old[i] + p)(x[i])` = sig_old[i] hashed p more times, then:

```
H^(d - ss_new[i])(H^(ss_old[i] + p)(x[i])) = H^d(x[i])
H^(d - ss_new[i] + ss_old[i] + p)(x[i]) = H^d(x[i])
```

This works when: **d - ss_new[i] + ss_old[i] + p = d**

Therefore: **ss_new[i] = ss_old[i] + p**

This means **ss_new[i] ≥ ss_old[i]** (we can hash forward but not backward)

### Crafting Our Messages

**First message:** Choose values less than the admin vector

```
[6, 0, 6, 0, 6, 0, 6, 0, 6, 0, ...]
```

- Even positions: 6
- Odd positions: 0

This is represented by: `\x60` repeated 32 times

**Second message:** Must be greater than the first

```
[6, 1, 6, 4, 6, 13, 6, 9, 6, 14] + [15, 15, ..., 15]
                                    (27 elements)
                                    (maximized in base 16)
```

This is: `admin` + `\xff` × 27

### Calculating the Differences

```python
differences = [0, 1, 0, 4, 0, 13, 0, 9, 0, 14, 9, 15, 9, 15, ..., 9, 15]
```

For positions 10-63:

- Even positions (10, 12, 14, ...): difference = 9 (from 6 to 15)
- Odd positions (11, 13, 15, ...): difference = 15 (from 0 to 15)

For the checksum positions (c₁, c₂):

- Old message sum: 6×32 = 192, so c_old = 960
- Old checksum: c_old = 15 × 64 - (6×32) = 960 - 192 = 768 → [c_old₁, c_old₂] = [48, 0] in base 16
- New message sum: 6+1+6+4+6+13+6+9+6+14 + 15×54 = 71 + 810 = 881
- New checksum: c_new = 15 × 64 - 881 = 79 → [c_new₁, c_new₂] = [4, 15] in base 16
- differences[64] = 4 - 48 (need adjustment)
- differences[65] = 15 - 0 = 15

- Old message

```python
m_old = [ 6, 0, 6, 0, 6, 0, 6, 0, 6, 0, 6, 0, 6, ..., 0 ]
```

    sum: 6×32 = 192
    c_old = 960 - 192 = 768
    768 = 3 * 16^2  → [ 3, 0, 0 ]
    the function int_to_vec subscribes the last digit if it greater than
    [c_old₁, c_old₂]= [ 0, 3 ]

- New message

```python
m_new = [0, 1, 0, 4, 0, 13, 0, 9, 0, 14, 15, 15, ..., 15 ]
```

    sum: 6+1+6+4+6+13+6+9+6+14 + 15×54 = 71 + 810 = 881
    c_new = 960 - 881 = 79
    79 = 4 * 16 + 15  → [ 4, 15 ]
    [c_new₁, c_new₂] = [ 4, 15 ]

- differences[64] = 4 - 0 = 4
- differences[65] = 15 - 3 = 12

### Forging the Signature

For each position i, hash the old signature by the difference:

```python
forged_sig[i] = hash_chain(sig_old[i], differences[i])
```

---

## Exploit Script

```python
import hashlib
import ast
from pwn import *

def get_hash(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def hash_chain(x: bytes, d: int) -> bytes:
    for _ in range(d):
        x = get_hash(x)
    return x

con = remote('nitwit.challs.pwnoh.io', 1337, ssl=True)

print(con.recvuntil(b"Public key: "))
pk_hex = con.recvline().strip().decode()
print("PK:", pk_hex)

# First message: [6, 0, 6, 0, ...] in base 16
m_old = b'\x60' * 32
con.recvuntil(b">>> ")
con.sendline(m_old.hex().encode())

print(con.recvuntil(b"Your signature is:\n"))
sig_line = con.recvline().strip()
sig_old = ast.literal_eval(sig_line.decode())

# Second message: "admin" + padding
admin_str = b"admin"
padding = b'\xff' * 27
m_new = admin_str + padding
assert len(m_new) == 32

# Calculate differences
forged_sig = list(sig_old)

differences = [0] * 66
differences[1] = 1
differences[3] = 4
differences[5] = 13
differences[7] = 9
differences[9] = 14

for i in range(10, 64):
    if i % 2 == 0:
        differences[i] = 9  # (15 - 6) = 9
    else:
        differences[i] = 15

differences[64] = 4
differences[65] = 12

# Forge the signature by hashing forward
for i in range(66):
    if differences[i] > 0:
        forged_sig[i] = hash_chain(sig_old[i], differences[i])

# Submit forged signature
con.recvuntil(b">>> ")
con.sendline(m_new.hex().encode())

con.recvuntil(b">>> ")
con.sendline(repr(forged_sig).encode())

# Get the flag!
print(con.recvline())
print(con.recvline())
print(con.recvline())
```

---

## Flag

```
[┤] Opening connection to nitwit.challs.pwnoh.io on port 1337: Trying 13.59.87[+] Opening connection to nitwit.challs.pwnoh.io on port 1337: Done
b'Welcome to my signing service!\nPublic key: '
PK: b524615c67d91cb8baeae128ee4bc979fd0f33852be61243cf07d66828c50cfd
b'Your signature is:\n'
b'[b\'\\x1b\\x0f\\xd9k\\x17GU\\x87\\xccM3\\x80e>\\x1cs\\xe4\\x0f\\xb5z\\xeb\\xf0`\\xb9\\x96\\x08\\x9d\\x89T\\x01\\x00\\xad\', b\'b}{\\xd2\\x86"J\\xb4\\xd2\\xc2]\\x10\\x01\\x04\\xb3\\x14\\xa8R\\x993\\x17\\xbe\\xad/g\\xd6\\x86\\xb9\\x8ay\\x08\\xbb\', b\'\\xcc\\xeea\\xedg\\xbd\\x9d\\xe2p\\xe7\\x7f\\xa9\\x8b\\xca(M\\x8e\\xf6\\x99\\xc1\\x13=\\xf5\\xd2\\xbc\\xbf\\x8b\\x9b\\xfb\\x99rO\', b\'\\x1d\\x1a\\xa8\\x8b|k\\xcb\\xda\\xe1n\\x9c\\x1fU)\\xf2\\x05&\\x17\\xc9\\xd5>\\x14\\xc5\\xd3\\x8f\\x0f\\xdb\\xbeL\\xed3\\xcc\', b\'\\xec\\x8d\\x81\\xadb\\xb1\\xc6\\xe1\\xe1\\xce\\xe5t\\x9f\\xdf\\x10I\\x0c\\xc0\\x940\\xb4 &~~+D\\x92V\\x19\\xcaL\', b\'\\xccuj6y\\xb6#\\xef\\xac\\x00\\x97<\\x1bT\\xb6\\xb8$\\xd8\\xc9\\t7\\x1d\\r\\xa0\\xf6\\r\\xca\\x9dcFu\\x12\', b\'\\xde\\xa8\\xc9\\xb5\\xd5^\\x98\\xf4D=2h\\x903\\xb8\\xfc\\xd3Gx\\xf7\\x90 \\xd9\\xfez\\x18\\x06a\\xad?\\xf8\\x9e\', b\'\\x96\\x8d\\x95ZH\\x8aKO\\xa6\\xe0Y_\\xaag\\xe5x(\\x1c\\x1e\\xaf\\x98\\xae\\x0e\\x90\\xadt=\\xaf\\xcdP\\x0e>\', b\'\\xf3\\xa6\\n\\xc2\\x02U\\xe6\\xcfl\\x90>h\\x90\\x1cX\\xfb\\x1a\\xe2\\x98\\xc8\\xdc\\x97\\xd3j\\x81\\x9b\\xab\\xda%\\xd8Z1\', b\'\\xbd\\x88\\x1f\\\\Wq\\xe6\\xc3\\x81\\xbd\\x89+\\x93\\xf5Ts\\xff4\\xec"Z\\x07Mk\\xef1\\xbd\\x1e\\xbe\\xa5T\\xb5\', b\'f\\xdeq\\x0b\\xb6\\xc5\\x12$\\x84\\xb7\\x82J\\xb7\\xe4\\xf24n!\\xdc\\xbf\\xc9\\xc8\\x97\\xf3\\xda\\xf1GL\\xc7\\xa30j\', b\'\\xe0^]S4\\xd4\\xf3\\xf0\\x17\\xb2\\r\\x97Ci\\xbfc\\xf2J:\\xdc\\xcf\\xe28\\xc3\\x08\\x80\\xa12\\xd4\\xcf\\xa5V\', b\'\\xc4u\\x90\\x11\\xff\\xfdN\\x8c()s\\xd6\\x19\\xb8\\xd49L\\xdb\\x94Fx\\x16\\x04^\\xf0\\xc5\\xb8\\xfb\\x94\\xa2\\x1e~\', b\'\\x83f\\xbb\\xcf\\xb8]q\\xaa\\xfa{\\xb4\\x14\\x83\\x16!\\tE\\xae\\xf6u0\\x84\\x8f/u\\xfb\\x16\\xadI\\x0f\\x0c\\x8e\', b\'[#c\\x8e\\t\\x8c\\\\^E\\x88\\x98\\xaa\\xd9\\x1f\\x17\\x18\\x17\\xc4@\\x80\\x81\\x00\\xf8\\xd9\\xc5>\\x9f\\xa0\\x81b\\xd7\\n\', b\'\\x0eV\\x88\\rG\\x81\\xea\\x1b=\\xe4m\\xb3V\\xd4Cjf\\xb1v$V=\\xf4\\xa4O\\xeb\\xab\\x8d3\\x9d{\\x05\', b\'\\x8bX\\x12\\xa3\\xac\\x05\\n\\xd8\\xfe\\n\\xf3\\x8ew\\xe1L\\x96\\xb08[6\\xef\\x8eE\\xa2\\xafv5}\\x0ez=\\x05\', b\'?*G}\\xeb\\xdb\\x1dm\\xad{\\xd8\\x03B\\xf0\\x01,\\xeb\\x92[c\\x84\\x91\\xc4\\xa1W#\\xd4f\\x1b\\xfd_>\', b\'\\xd2[\\x18\\xb6\\xac\\xe6\\xfc\\x19\\xf6\\xab\\xba\\xcd%\\xbb\\x0f\\x18V\\xa9&\\xd5Xi\\xb7\\x8f\\xbfS\\x08\\xa4\\xe0&\\xd7\\xda\', b"L4\\xbc\\xf2>\\xb6+s\\x93\\xef~K\\x93\\x83\\xdf\'\\xe24\\xd8C}\\xfd)\\xc9}W\\x11\\x84\\x9e\\xe3E\\x06", b\'`\\xdf\\x87\\xf76T\\x97\\nK5\\x94W,\\x07FV\\xd3\\xfd\\x08\\xb6g\\xf5\\x0c\\xac\\xed\\x89\\xe1\\xc2$\\x03\\x17\\xcc\', b\'\\x0b\\xf4\\xcb\\xca\\x9a\\xe45\\xcc\\xd1\\xaae\\xc9\\xfa\\\';Z\\x91F\\xdd\\xde"s\\x17\\x1f\\xe4\\x9d\\x83\\xff\\xeb\\x91\\x1c \', b\'A@\\xde\\xc9u\\xba\\x93_\\x1a^e\\xb0r\\x8e_\\x1d{d\\xfe\\x80\\xae\\x9d\\x0f\\xa2\\xf7=1\\x03\\xe7\\x0c_o\', b\'#yV\\x98\\xc3\\x038\\xd4\\xa3\\xc7\\xdd\\x8f\\x0f\\x81\\x08;\\x00o,;\\xac&f4\\x83;q.\\x1a}\\x036\', b\'V?n\\xe8\\xe0Jy\\xc8-5\\x15]yY\\xdf\\x16[\\xf7x\\r\\xe3\\xb3\\x97\\xc1\\x84\\x1f\\x90\\xfcI\\xe1\\xfc\\x04\', b\'\\r\\xe1\\xe6\\x93\\xcf\\x90\\xaa\\xba\\xe5\\x14\\xceL\\x89M<$\\x88d\\xa9\\x9f\\xd3\\x1a\\x11!\\x90\\xacG\\x90\\xcd\\xf1\\x07-\', b\'Z\\xe0\\n\\x0f\\xe8\\x95\\xf2\\xf9\\x8dwA\\x86\\xe766\\xd2L\\x96kf\\x80\\xb1\\x14\\x81_\\x0b[%\\xcb\\xe5\\xd2\\xdd\', b\'\\xba\\xa5\\xa7@3\\x8d\\xe0\\x92UxZ\\x8a\\xa5\\x12\\x81\\x8bYI\\xac\\xee|\\x8d*P\\x85W\\x8bp\\x9d\\x14.\\x18\', b\'\\xa3(Y\\xcb\\xf0O\\x9f\\xf6@\\xa3s\\x8c=\\xa4\\xddFp\\x06\\xcb\\x03\\xc9\\x15}I5\\xdfI\\x87\\xe1\\xd9\\x9e\\xb6\', b\'s]E\\xa5=\\xdf\\x8eiL\\xf4V\\xe0\\xb5\\xce\\x99Z\\x91\\x82\\xdf\\x81\\xb5\\xca\\xfau)r\\x8e6\\x07\\xb2\\x19\\r\', b\'\\xcddA|\\xb9?\\x1a\\xc4OGp\\x07R\\x86\\x8bd\\xba\\xe06\\x0bYV\\x92r\\xc1\\xf6a\\xdf\\xa3$w?\', b\'\\x9dk\\xbe\\x163\\x87Ax\\x10\\xbedJ\\xc6\\xfa\\xe1\\xcb.\\x82~,\\x93Z\\xdf\\xd4\\xc6\\x19H\\xd6\\xa0\\x13\\x1d\\xf5\', b\'\\xe2IiN.\\xff\\x02B\\x17Mr\\x87\\x03\\xb1\\x14\\xaf\\x19\\x90\\xe7\\xb9\\x8b\\x07\\xf8-p6\\x86a\\xd8\\xb02}\', b\'\\xa2\\xc2f\\xe7\\xd8:\\x1f\\x12"rq4Q\\x96\\xe6^\\xc2\\xf3\\xcb\\xcf_>\\x12CT\\xde\\xc1\\xd9\\xe0\\xc3\\\'\\xce\', b"\\tN\\xc1CVBkig\\xf0\\x10\\x8aRz\\xc4\\x92\\x1c\\\\\'z\\x19\\ndO\\xd1\\xbb\\xf1\\x19\\xbc\\x13\\x11,", b"k\\x82\\x02\\xbd\\xf9\\x99MI=#R\\xff9\\xc1r\\xe3S\\xc9\\x8c\\x12gF\\xc3\\xa5\\xd7\\x98\\xbeb+\'\\x88\\x8b", b\'\\xcb\\xa7b\\xe4\\xa2e\\x93\\xf6G7\\x00\\x15W5\\xd9\\xfb\\xbc\\x84H5f\\xda4\\xf6\\xa3I!@\\xeb\\xd4\\xa2\\x15\', b\'xg)d\\xab\\x07L\\xc8\\x14\\xb4\\x89\\xd9\\x9c|,\\x0br\\xa5\\x18p\\xbd\\x14\\x00\\xc3\\x05OPF\\xee\\xa6\\x06q\', b\'\\x95`\\xd3Gv\\xbeq\\xb9\\xc8\\xcen\\x94!\\x1e\\xfe\\xc0\\x1bV\\xa4\\xd6\\xbc\\xc2\\x02j\\x9b\\xe5\\xf3\\x0c\\xe4\\x98_\\n\', b"\\xb0J\\xca\\x1djR\\xa2\\xb8\\x14\\x0f\\xad\\xeb\'K\\x0eyNK%\\x0f\\xef2\\xd1\\x92\\xc1@\\xf4\\xd8\\xa3\\x846;", b"\\x16P:R\\x1e\\xea\\xb2\\x02\\xfc\\xb9k_\\x94\\x11\\xb5\\xbe\\x01\\xc27\'\\x08\\x87]\\xd2j\\xcb\\x02S\\xe5\\xbeE@", b\'\\xbd\\xee\\xc5\\xf4\\xa5\\x91\\x85ki\\xed\\xc5\\x0e\\xe2}]\\xf2\\xa9\\x9c\\x0f-|1\\xaf\\x02\\x87U4$\\xa2\\xfcO\\xa8\', b\'5U\\xf6"k\\xaaM\\x08\\x8c\\x9f\\x1e\\xeb\\xccE\\xd5\\x83 \\xbd\\xdeI\\x98\\x01k\\xfa\\x11:\\xd7\\x83\\x97\\xfdV\\xf3\', b\'V\\xe8\\x9e\\xe5p\\x85\\x04U"+\\xc1KP\\\'S\\xe5\\x0b\\x01X#\\xa2\\xcft,\\xcf\\xfer\\xde\\x8bi\\xbf\\xe2\', b\'\\xa8T\\tY?`\\xf8\\xa1\\x838\\x1f"y\\xad\\xdc^y)s\\x9e10\\xb4\\xa02\\x03\\xaf\\xd3\\xac\\x01Mz\', b\'\\xcc\\x98\\x18c\\x17\\xcf\\x14\\xe0\\xbf\\x85\\xb4\\xde\\xe8\\xca3\\xcf\\xb8U\\xe8G%\\xaf\\x82\\xdaD\\xd8*\\xf9\\xe3\\\\g\\t\', b\'\\xd9_V\\xaay\\x90\\x99\\xf9\\xc0\\x82\\xb3\\x966 \\x86\\xe2\\xe3\\x12\\x10\\x1c\\xa95M\\x1e,_\\x02A\\xbb\\xc6\\xe0/\', b\'N\\xb5\\x9c\\xca\\xf6\\x7f8o\\xf1\\xe6\\x85\\x08-=u\\xf7\\x01\\xc7\\xbe2e\\xcb2\\x1ds\\xd8G\\xafE\\xa0\\xcc\\x00\', b\'(\\x89\\xcf\\x1b\\x8d\\xd7\\xb3t\\x83\\x0f^\\x1c|"\\xd7\\x1a&\\xc3q\\xed(\\xc3\\xf7\\xe9e\\x1c\\x8dXe\\x04\\x14m\', b\'\\xcf7\\xbc\\x90\\xbf8K\\x9f\\xa1<:t-LA$;R\\xd2$\\x9eG\\xdb\\x1e"\\x01\\xfc$AYR\\xfa\', b\'\\x06\\xcc\\x0e\\xf4\\xdcb\\x9c\\xe4\\xec-X#\\xb7\\xb9t\\xf3W4\\xb9B+t\\x8a\\x00\\x1e\\xed\\xe8\\xd1\\xeaTB2\', b\'\\xfdx\\xc8;l^\\x84.d"\\xeb\\xacTQ\\x99\\xaa\\x8f\\xfb]\\xe8\\x86\\x17\\x80vx\\x90e\\xaf\\xd4\\x12b-\', b\'?\\x13\\xd5\\xbc\\x97\\t\\xacP\\xecd\\x8a\\xb6a3j^\\x95\\x81\\xcfj^\\xff\\x12\\xb9d\\xb1\\x89M\\xb4M-\\xba\', b\'l%*K\\x0fYo\\x0e\\xe1\\xdbGqQ\\xd0\\xda\\x86-\\xa5r\\x10@\\xfcY\\x10\\xee\\xc0gc\\x10\\x96C\\xff\', b\'\\xd3\\xef\\xbe<\\x96\\xc3i\\xce\\xb3QY\\xcf\\x1d\\x7f\\xe1_jB\\xda\\xe4<\\x19e\\xc5\\r\\xfd\\xb1\\xf6\\xb4\\xe9/7\', b\'#]c>\\x12\\r\\x8bT\\x05\\xfc\\xeb\\xa8\\x81\\xe6\\xf1\\xc4\\xae\\x15\\xa2|3\\xad!\\xad\\xa9\\x8dw,7\\x1de\\x83\', b\'\\xe7\\x0c\\xdbcH)\\xbf\\x85\\x1c|l\\x9bZ~\\xd3\\x1e\\xc5\\xee4v\\x920^\\xb5\\xad\\x8b\\xc2\\xb6i\\xcc\\xee}\', b\'&\\xd8\\xfe6"\\x98\\x9c`\\x8a_P`\\xb5\\xb1W\\x19\\xc5H\\xa3su\\xc1x\\xaa\\xa9\\xfc-\\x9f\\xae\\xa8T\\xba\', b\'\\xe2\\xfaR\\xd4R\\x17\\xc9v\\xa6G\\xf4\\xe1V\\x07\\n\\xebg\\x8d\\xdcL\\r\\x80vB\\x85\\x8f\\xa0\\x92\\x1ev\\xcbL\', b\'\\x9a\\n\\x82ol\\xb3\\xd2\\x05}"\\x00\\x14\\xb1S`0\\xb7\\xbb\\x88\\x98<\\x16\\xb1\\t\\x11\\x9ev|\\xcc\\x84\\x9e\\x9a\', b\'\\xf0\\xf0\\x9f\\xec\\x11\\x8b\\x01\\xbes\\xb8\\xee\\xa0\\xdbY\\xef\\x7f\\x8eS\\xd7\\x87\\xf8\\xc0\\xe4\\x1b\\x9e\\xa6\\xfa\\xd1|\\x8c\\x95\\x0b\', b\'`g\\x8a\\xadG \\x81\\xc0N6\\x8fT\\xab\\x98\\x0c\\xaaz\\x12\\xfa\\x06\\xad\\x1d=\\x1bR\\x9b\\x0b3\\x9a*\\xc1\\xb6\', b\'\\x84\\x8cyjL\\xc8N!aWE&\\x88\\xd9C\\xa22\\x00\\xfa\\x8a\\x8d\\xfcVKo5L\\xac\\xeaVpI\', b\'vd\\xe7kV\\xc2\\xdeq\\xcf\\x10E\\x96\\xfa\\xf2\\x1c\\x9b0\\xf3\\xe2\\xb9\\r$\\xa86\\xd1\\xe9\\xbe#\\xd1\\\\Y\\xba\', b\'\\x9d?\\xfa\\x00r\\x1e\\x1c\\xe0"u|r\\xe7\\x88\\x87\\xa4z\\x06]\\x85\\x14\\xabw\\xcb\\x8cEE-<e\\x03\\xec\', b\'\\x1c\\xc3}\\xea\\x19\\xff\\x9b^\\xeb\\\\i\\x85C\\x99\\x01\\x10\\xbe\\x02B0D\\x10T\\xae\\xa3\\xf7\\xab\\xdb\\xb4\\x1c\\x15\\xbb\']\n'
b"You must be the admin, so here's your flag:\n"
b'bctf{i_f0rg0t_h0w_t0_r3ad_m4th_n0t4t10n}\n'
[*] Closed connection to nitwit.challs.pwnoh.io port 1337
```
