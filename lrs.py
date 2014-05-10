import sys

from fractions import gcd
from hashlib import sha512
from random import Random

from Crypto.PublicKey import DSA

import daga
from daga import P, G, Q


# Get some randomness. (insecure atm for demonstration purposes)
Rand = Random()

class Signer:
    def __init__(self, priv_key, index, pub_keys, group_gen, tag):
        self.priv_key = priv_key
        self.index = index
        self.pub_keys = pub_keys
        self.group_gen = group_gen
        self.tag = tag

    def sign(self, msg):
        h = sha512()
        h.update(daga.elem_to_bytes(self.group_gen))
        h.update(daga.elem_to_bytes(self.tag))
        h.update(msg.encode("utf-8"))
        precompute = int.from_bytes(h.digest(), 'big')

        u = Rand.randrange(Q)
        s = [0] * len(self.pub_keys)
        c = [0] * len(self.pub_keys)

        h = sha512()
        h.update(daga.elem_to_bytes(precompute))
        h.update(daga.elem_to_bytes(pow(G, u, P)))
        h.update(daga.elem_to_bytes(pow(self.group_gen, u, P)))
        c[self.index] = int.from_bytes(h.digest(), 'big')  % Q

        count = len(self.pub_keys)
        for i in range(1, count):
            idx = (i + self.index) % count
            s[idx] = Rand.randrange(Q)
            h = sha512()
            h.update(daga.elem_to_bytes(precompute))

            tmp = pow(G, s[idx], P) * pow(self.pub_keys[idx], c[idx-1], P) % P
            h.update(daga.elem_to_bytes(tmp))

            tmp = pow(self.group_gen, s[idx], P) * pow(self.tag, c[idx-1], P) % P
            h.update(daga.elem_to_bytes(tmp))

            c[idx] = int.from_bytes(h.digest(), 'big') % Q

        s[self.index] = (u - self.priv_key * c[self.index-1]) % Q
        return (c[-1], s, self.tag)

class Verifier:
    def __init__(self, pub_keys, group_gen):
        self.pub_keys = pub_keys
        self.group_gen = group_gen

    def verify(self, msg, sig):
        commit, s, tag = sig

        h = sha512()
        h.update(daga.elem_to_bytes(self.group_gen))
        h.update(daga.elem_to_bytes(tag))
        h.update(msg.encode("utf-8"))
        precompute = int.from_bytes(h.digest(), 'big')

        c_commit = commit
        for i in range(len(self.pub_keys)):
            z_i = (pow(G, s[i], P) * pow(self.pub_keys[i], c_commit, P)) % P
            z_ii = (pow(self.group_gen, s[i], P) * pow(tag, c_commit, P)) % P
            h = sha512()
            h.update(daga.elem_to_bytes(precompute))
            h.update(daga.elem_to_bytes(z_i))
            h.update(daga.elem_to_bytes(z_ii))
            c_commit = int.from_bytes(h.digest(), 'big') % Q
        return commit == c_commit

def example():
    MEMBERS = 35
    keys = [daga.random_dh_key() for i in range(MEMBERS)]
    pub_keys = [pow(G, c, P) for c in keys]
    h = sha512()
    for key in pub_keys:
        h.update(daga.elem_to_bytes(key))
    group_gen = pow(G, int.from_bytes(h.digest(), 'big') % Q, P)
    tags =  [pow(group_gen, keys[i] , P) for i in range(MEMBERS)]
    msg = "hello world!"

    signer = Signer(keys[3], 3, pub_keys, group_gen, tags[3])
    sig = signer.sign(msg)
    verifier = Verifier(pub_keys, group_gen)
    assert verifier.verify(msg, sig)
    print("Well, that seemed to work.")

if __name__ == "__main__":
    example()
