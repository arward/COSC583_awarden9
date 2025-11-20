# Alex Warden
# COSC583
# Blockchain Lab

import hashlib

def main():

    difficulty = 24

    # Hash and quote from passoff server (Hardcoded and you have to change it everytime cuz I was LAZY!)
    lasthex = "000000c9c8c8f62136c03f66b68591834ba5c6d86d167dd70d46b8f7f77d985e"
    lasthash = bytes.fromhex(lasthex)

    quote = ("Only bad designers blame their failings on the users. -- unknown")
    nonce = 0

    while True:
        # Convert nonce to big endian bytes
        if nonce == 0:
            nonbytes = b"\x00"
        else:
            length = (nonce.bit_length() + 7) // 8
            nonbytes = nonce.to_bytes(length, "big")

        # Convert the quote string to ASCII bytes
        quotebytes = quote.encode("ascii")

        # Hash: H( H(prev) || nonce || quote )
        data = lasthash + nonbytes + quotebytes
        blockhash = hashlib.sha256(data).digest()

        # Verify the first bits are zero
        fullbytes = difficulty // 8
        rembits = difficulty % 8

        zeros = True

        # Check the full zero bytes
        for i in range(fullbytes):
            if blockhash[i] != 0:
                zeros = False
                break

        # Check the remaining partial byte bits
        if zeros and rembits != 0:
            mask = (0xFF << (8 - rembits)) & 0xFF
            if (blockhash[fullbytes] & mask) != 0:
                zeros = False

        # If proof of work satisfied, we are done
        if zeros:
            print("\nNonce :")
            print(nonce)
            print("\nBlock hash :")
            print(blockhash.hex())
            break

        nonce += 1

main()
