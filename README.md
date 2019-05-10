# SPN signature scheme

Demonstration of the signature scheme from the paper:

Pavol Zajac: Code-based signature scheme derived from a MRHS representation of an AES encryption. Central European Conference on Cryptology 2019.

Use from SAGE command line:

load('spnsign.sage')

key = randint(0, 0xffff)
pi  = Permutations(12).random_element()

PK = getPK(key, pi)

msg = randint(0, 0xffff)
sig = getSignature(msg, key, pi)

verify(sig, PK) == 0

sig[0] = 15 - sig[0]
verify(sig,PK) == 0
