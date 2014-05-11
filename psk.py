import sys

from fractions import gcd
from hashlib import sha512
from random import Random

from Crypto.PublicKey import DSA

import daga
from daga import P, G, Q


# Get some randomness. (insecure atm for demonstration purposes)
Rand = Random()

"""
Implements an authenticating agent that authenticates a new 
member against a list of public keys. The joining member also
authenticates the leader.

This authentication protocol is Protocol 9.6 in Stinson's 
"Cryptography: Theory and Practice" (Third Edition). 
In our implementation, the leader (authenticator) takes the
role of Alice, while the client (authenticate) takes the role
of Bob.

1) Bob chooses a random challenge r_B and sends (PK_B,r_B)
  to Alice
2) Alice chooses a random challenge r_A and signs:
    y_A = sig_A(PK_B, r_B, r_A)
  She sends (PK_A, r_A, y_A) to Bob
3) Bob accepts Alice if the signature verifies. Bob
  then computes y_B = sig_B(PK_A, r_A) and sends y_B to Alice
4) Alice accepts if the signature is valid.
"""

class Alice:

    def __init__(self, priv_key, pub_key, pub_bob):
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.pub_bob = pub_bob
        self.rand_alice = Rand.getrandbits(P.bit_length())

    def handle_challenge(self, rand_bob):
        self.rand_bob = rand_bob
        sig_alice = daga.dsa_sign(self.priv_key,
                self.pub_bob + rand_bob + self.rand_alice)
        return (self.rand_alice, sig_alice)

    def verify_challenge(self, sig_bob):
        daga.dsa_verify(self.pub_bob, self.pub_key + self.rand_alice, sig_bob)
        return True

class Bob:

    def __init__(self, priv_key, pub_key, pub_alice):
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.pub_alice = pub_alice

    def prepare_challenge(self):
        self.rand_bob = Rand.getrandbits(P.bit_length())
        return self.rand_bob

    def verify_challenge(self, rand_alice, sig_alice):
        daga.dsa_verify(self.pub_alice, self.pub_key + self.rand_bob + rand_alice, sig_alice)
        return daga.dsa_sign(self.priv_key, self.pub_alice + rand_alice)

def example():
    priv_alice = daga.random_dh_key()
    pub_alice = pow(G, priv_alice, P)
    priv_bob = daga.random_dh_key()
    pub_bob = pow(G, priv_bob, P)

    alice = Alice(priv_alice, pub_alice, pub_bob)
    bob = Bob(priv_bob, pub_bob, pub_alice)

    daga.dsa_verify(pub_alice, "test".encode("utf-8"), daga.dsa_sign(priv_alice, "test".encode("utf-8")))

    s0 = bob.prepare_challenge()
    s1 = alice.handle_challenge(s0)
    s2 = bob.verify_challenge(*s1)
    assert alice.verify_challenge(s2)
    print("Well, that seemed to work.")

if __name__ == "__main__":
    example()
