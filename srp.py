# Alex Warden
# COSC583
# SRP Lab

import random
import hashlib

# Fast modular exponentiation, square and multiply.
def fastmodexp(b, e, n):
    # Start with 1 because any base^0 = 1.
    product = 1
    # Each loop iteration processes one bit of 'e'.
    while e > 0:
        # Reduce base mod n at each step to keep values bounded.
        b %= n
        # If the current bit of 'e' is 1, multiply the product by base.
        if e & 1:
            product = (product * b) % n
        # Square the base for the next bit of the exponent.
        b = (b * b) % n
        # Shift the exponent right by one bit to process the next bit.
        e >>= 1
    # Return the final product — now equal to (b^e mod n).
    return product

# Convert integer to big-endian bytes.
def int_to_bytes(n):
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")

# SHA-256 hash, returns bytes.
def hash_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def main():
   
    g = 5
    p = 233000556327543348946447470779219175150430130236907257523476085501968599658761371268535640963004707302492862642690597042148035540759198167263992070601617519279204228564031769469422146187139698860509698350226540759311033166697559129871348428777658832731699421786638279199926610332604408923157248859637890960407
    a = 4945908088205637408766330865184400910798255945753418370705468866067419357494

    pubkey = fastmodexp(g, a, p)

    print("\nPublic key g^a:")
    print(pubkey)

    netid = "awarden9"        
    password = "nimblest"
    salt_hex = "a9e35eb1"
    b = "178573507988243316848127301579564809036819696753006890273263246777917097570602221972762253989362986158387887432597248337978723913691172136293465859262814462092289291139387748978071490636489716994854327888445978255820027495480895779710806635451173271200643852440935317197980391503191192706873392362169826073735"          # \bar B as decimal string

    salt = bytes.fromhex(salt_hex)
    Bbar = int(b, 10)

    # x = H(salt || password)^1000
    data = salt + password.encode("ascii")
    digest = data
    for i in range(1000):
        digest = hash_bytes(digest)
    x = int.from_bytes(digest, "big")
    print("\nHashed password :")
    print(x)

    # k = H(p || g)
    Hp_g = hash_bytes(int_to_bytes(p) + int_to_bytes(g))
    k = int.from_bytes(Hp_g, "big")
    print("\nk :")
    print(k)

    # g^b = B̄ - k * g^x (mod p) = B - k * v (mod p)
    v = fastmodexp(g, x, p)
    gb = (Bbar - (k * v) % p) % p
    print("\ng^b :")
    print(gb)

    # u = H(g^a || g^b)
    H_ga_gb = hash_bytes(int_to_bytes(pubkey) + int_to_bytes(gb))
    u = int.from_bytes(H_ga_gb, "big")
    print("\nu :")
    print(u)

    # Shared = (g^b)^(a + u*x) mod p
    exponent = a + u * x
    shared = fastmodexp(gb, exponent, p)
    print("\nShared key :")
    print(shared)

    Hp = hash_bytes(int_to_bytes(p))
    Hg = hash_bytes(int_to_bytes(g))
    Hnetid = hash_bytes(netid.encode("ascii"))

    # H(p) XOR H(g)
    Hp_xor_Hg = bytes(x ^ y for x, y in zip(Hp, Hg))

    ga_bytes = int_to_bytes(pubkey)
    gb_bytes = int_to_bytes(gb)
    shared_bytes = int_to_bytes(shared)

    # M1 = H( H(p) ⊕ H(g) || H(netId) || salt || g^a || g^b || shared key )
    M1_bytes = hash_bytes(
        Hp_xor_Hg +
        Hnetid +
        salt +
        ga_bytes +
        gb_bytes +
        shared_bytes
    )

    # M2 = H( g^a || M1 || shared key )
    M2_bytes = hash_bytes(
        ga_bytes +
        M1_bytes +
        shared_bytes
    )

    print("\nM1 :")
    print(M1_bytes.hex())
    print("\nM2 :")
    print(M2_bytes.hex())

main()
