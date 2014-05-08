import sys

from fractions import gcd
from hashlib import sha512
from random import Random

from Crypto.PublicKey import DSA

# Get some randomness. (insecure atm for demonstration purposes)
Rand = Random()

# Here are a 1024-bit safe prime and generator of the (P - 1)/2 order subgroup I
# computed myself. Sketchy, eh?
P = 124325339146889384540494091085456630009856882741872806181731279018491820800119460022367403769795008250021191767583423221479185609066059226301250167164084041279837566626881119772675984258163062926954046545485368458404445166682380071370274810671501916789361956272226105723317679562001235501455748016154806151119
G = 99656004450068572491707650369312821808187082634000238991378622176696343491115105589981816355495019598158936211590631375413874328242985824977217673016350079715590567506898528605283803802106354523568154237112165652810149860207486982093994904778268429329328161591283210109749627870113664380845204583563547255062
# Same but 2048 bits.
#P = 27927669199745897480192475403549047216554821662794619165264080639365983255644502375016459217363557816327075710968347577873413531747870995166422966792624628587167099967144352300048688249456511457979188066202485263624876864910790966741324232833539527331240187344632772769944302133859635686652694913901774899716176061200063018486234819466278861754046014136602565681682003785393029271730863251114264009567886052085968472025049680504208350286215846649746729345007798729883244031805808718908355554734961706377253224661315024764137163937689747019988805788185103825179357586792027111676659314369039503661013404299535644931247
#G = 23980964643883997791973764119191343485108478268280187273764110016399758928327299356108443446373039955957739682198803936401869820784993184164369945936082779776397447285391214903950439069492767520728971994214558690769765835532813393423832851620613473408517190997814318932462267642122812979432918572951500898997160033670018434913752563529697839833229914557436668909155867344351296361166233129153503324601602877106470219704921071920596364745260042707475245689874318235973443988270541192532588923789966556622843304211912625888536185817353753787604914145051372838321501368259242189807240634790337143910180278807098418984824
Q = (P - 1)//2 # Order of subgroup G generates.


def random_dh_key():
    # The secret should be the same bit length as P.
    return Rand.randrange(1 << (P.bit_length() - 1), P - 1)


def dsa_sign(priv, msg):
    if isinstance(msg, int):
        msg = msg.to_bytes((msg.bit_length() // 8) + 1, 'big')
    msg = sha512(msg).digest()
    dsa = DSA.construct((pow(G, priv, P), G, P, Q, priv))
    k = Rand.randrange(1, Q)
    return dsa.sign(msg, k)

def dsa_verify(pub, msg, sig):
    if isinstance(msg, int):
        msg = msg.to_bytes((msg.bit_length() // 8) + 1, 'big')
    msg = sha512(msg).digest()
    dsa = DSA.construct((pub, G, P, Q))
    if not dsa.verify(msg, sig):
        raise ValueError("dsa verification failed")


class ClientAuthState:

    def __init__(self, ac, ephemeral_public_key, s, initial_linkage_tag, commitments):
        self.ac = ac
        self.ephemeral_public_key = ephemeral_public_key
        self.s = s
        self.initial_linkage_tag = initial_linkage_tag
        self.commitments = commitments


class AuthenticationContext:

    def __init__(self, client_keys, server_keys, server_randomness, generators):
        self.client_keys = client_keys
        self.server_keys = server_keys
        self.server_randomness = server_randomness
        self.generators = generators

    def verify_dishonest_client_proof(self, p):
        t1 = pow(p.client_ephemeral_public_key, p.r, P)*pow(p.assertion, p.c, P) % P
        t2 = pow(G, p.r, P)*pow(self.server_keys[p.server], p.c, P) % P
        h = sha512()
        for thing in [p.assertion, p.client_ephemeral_public_key, self.server_keys[p.server], G, t1, t2]:
            h.update(elem_to_bytes(thing))
        if int.from_bytes(h.digest(), 'big') != p.c:
            raise ValueError("client dishonestly proof not valid")


class Client:

    def __init__(self, client_id, private_key):
        self.id = client_id
        self.private_key = private_key

    def prepare_client_auth_request(self, ac):
        ephemeral_private = random_dh_key()
        last_commitment = G
        commitments = []
        initial_linkage_tag = ac.generators[self.id]
        s = 1
        for server_public in ac.server_keys:
            shared_secret = compute_shared_secret(pow(server_public, ephemeral_private, P))
            s *= shared_secret
            s %= Q
            last_commitment = pow(last_commitment, shared_secret, P)
            commitments.append(last_commitment)
            #if server_public == ac.server_keys[1]:
            #    commitments[-1] = 42
            initial_linkage_tag = pow(initial_linkage_tag, shared_secret, P)
        return ClientAuthState(ac, pow(G, ephemeral_private, P), s, initial_linkage_tag, commitments)

    def prepare_client_challenge_request(self, state):
        # Begin interactive proof that the client knows the private key.
        state.w = []
        state.v = []
        state.T = []
        last_commitment = state.commitments[-1]
        for i, client_public in enumerate(state.ac.client_keys):
            wi = 0 if i == self.id else Rand.randrange(0, Q)
            state.w.append(wi)
            v0 = Rand.randrange(Q)
            v1 = Rand.randrange(Q)
            state.v.append((v0, v1))
            T00 = pow(client_public, wi, P)*pow(G, v0, P) % P
            T10 = pow(last_commitment, wi, P)*pow(G, v1, P) % P
            T11 = pow(state.initial_linkage_tag, wi, P)*pow(state.ac.generators[i], v1, P) % P
            state.T.append((T00, T10, T11))

    def answer_server_challenge(self, state, challenge):
        i = self.id
        C = state.w[:]
        C[i] = (challenge - sum(state.w)) % Q
        R = state.v[:]
        R[i] = ((R[i][0] - C[i]*self.private_key) % Q), ((R[i][1] - C[i]*state.s) % Q)
        state.proof = ClientProof(C, R)

class ClientProof:

    def __init__(self, C, R):
        self.C = C
        self.R = R

class VerificationChain:

    def __init__(self, challenge, client_ephemeral_public_key, commitments, initial_linkage, client_proof):
        self.challenge = challenge
        self.client_ephemeral_public_key = client_ephemeral_public_key
        self.commitments = commitments
        self.initial_linkage = initial_linkage
        self.client_proof = client_proof
        self.server_proofs = []

    def check_server_proof(self, ac, i):
        # Compute commitments.
        p = self.server_proofs[i]
        previous_tag = self.server_proofs[i - 1].T if i > 0 else self.initial_linkage
        t1 = pow(previous_tag, p.r1, P)*pow(p.T, Q - p.r2, P) % P
        t2 = pow(G, p.r1, P)*pow(ac.server_randomness[i], p.c, P) % P
        prev_commit = self.commitments[i - 1] if i > 0 else G
        t3 = pow(prev_commit, p.r2, P)*pow(self.commitments[i], p.c, P) % P
        h = sha512()
        for thing in [previous_tag, p.T, ac.server_randomness[i], G, self.commitments[i], prev_commit, t1, t2, t3]:
            h.update(elem_to_bytes(thing))
        if int.from_bytes(h.digest(), 'big') != p.c:
            raise ValueError("verifying server {}'s proof failed".format(i))
        return True

def elem_to_bytes(i):
    return i.to_bytes(P.bit_length() // 8, 'big')

def compute_shared_secret(initial):
    s = int.from_bytes(sha512(elem_to_bytes(initial)).digest(), 'big')
    while gcd(s, Q) != 1:
        s += 1
    return s

def modular_inverse(a):
    # The modular inverse mod P - 1. a MUST be coprime to P - 1.
    b = Q
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q,r = b//a,b%a; m,n = x-u*q,y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    return x % (P - 1)

class ServerProof:

    def __init__(self, T, c, r1, r2):
        self.T = T
        self.c = c
        self.r1 = r1
        self.r2 = r2

class DishonestClientProof:

    def __init__(self, server, shared_secret, client_ephemeral_public_key, assertion, t1, t2, c, r):
        self.server = server
        self.shared_secret = shared_secret
        self.client_ephemeral_public_key = client_ephemeral_public_key
        self.assertion = assertion
        self.t1 = t1
        self.t2 = t2
        self.c = c
        self.r = r

class DishonestClient(Exception):

    def __init__(self, proof):
        super(DishonestClient, self).__init__()
        self.proof = proof

class Server:

    def __init__(self, server_id, private_key, secret):
        self.id = server_id
        self.private_key = private_key
        self.secret = secret

    def authenticate_client(self, ac, msg_chain):
        # First, check the client's proof.
        p = msg_chain.client_proof
        for i, (T00, T10, T11) in enumerate(msg_chain.challenge.T):
            ci = p.C[i]
            R0, R1 = p.R[i]
            if T00 != pow(ac.client_keys[i], ci, P)*pow(G, R0, P) % P:
                raise ValueError("client commit T00 doesn't match")
            if T10 != pow(msg_chain.commitments[-1], ci, P)*pow(G, R1, P) % P:
                raise ValueError("client commit T10 doesn't match")
            if T11 != pow(msg_chain.initial_linkage, ci, P)*pow(ac.generators[i], R1, P) % P:
                raise ValueError("client commit T11 doesn't match")
        if sum(p.C) % Q != msg_chain.challenge.C:
            raise ValueError("challenge doesn't match")

        # Now we check the previous server's proofs.
        for i in range(len(msg_chain.server_proofs)):
            msg_chain.check_server_proof(ac, i)

        # Compute our shared secret with the client and check the commitment.
        shared_secret = compute_shared_secret(pow(msg_chain.client_ephemeral_public_key, self.private_key, P))
        previous_commit = msg_chain.commitments[self.id - 1] if self.id > 0 else G
        if pow(previous_commit, shared_secret, P) != msg_chain.commitments[self.id]:
            # Some funny business is going on. Prove that the client is up to no
            # good.
            assertion = pow(msg_chain.client_ephemeral_public_key, self.private_key, P)
            v = Rand.randrange(Q)
            t1 = pow(msg_chain.client_ephemeral_public_key, v, P)
            t2 = pow(G, v, P)
            h = sha512()
            for thing in [assertion, msg_chain.client_ephemeral_public_key, pow(G, self.private_key, P), G, t1, t2]:
                h.update(elem_to_bytes(thing))
            c = int.from_bytes(h.digest(), 'big')
            r = (v - c*self.private_key) % Q
            p = DishonestClientProof(self.id, shared_secret, msg_chain.client_ephemeral_public_key, assertion, t1, t2, c, r)
            raise DishonestClient(p)

        # Compute intermediate linkage tag and generate proof.
        previous_tag = msg_chain.server_proofs[-1].T if self.id > 0 else msg_chain.initial_linkage
        tag = pow(previous_tag, self.secret*modular_inverse(shared_secret), P)
        v1 = Rand.randrange(Q)
        v2 = Rand.randrange(Q)
        t1 = pow(previous_tag, v1, P)*pow(tag, Q - v2, P) % P
        t2 = pow(G, v1, P)
        t3 = pow(previous_commit, v2, P)
        h = sha512()
        for thing in [previous_tag, tag, pow(G, self.secret, P), G, msg_chain.commitments[self.id], previous_commit, t1, t2, t3]:
            h.update(elem_to_bytes(thing))
        c = int.from_bytes(h.digest(), 'big')
        r1 = (v1 - c*self.secret) % Q
        r2 = (v2 - c*shared_secret) % Q
        my_proof = ServerProof(tag, c, r1, r2)
        msg_chain.server_proofs.append(my_proof)
        return msg_chain

class Challenge:

    def __init__(self, C, T):
        self.C = C # The actual challenge.
        self.T = T # Client commitments.

def example():
    CLIENTS = 32
    SERVERS = 3
    clients = [Client(i, random_dh_key()) for i in range(CLIENTS)]
    client_pub_keys = [pow(G, c.private_key, P) for c in clients]
    servers = [Server(i, random_dh_key(), Rand.randrange(1, Q)) for i in range(SERVERS)]
    server_pub_keys = [pow(G, s.private_key, P) for s in servers]
    server_randomness = [pow(G, s.secret, P) for s in servers]
    # The computation of generators should actually be done in a distributed
    # manner by the servers. If David provides distributed randomness, we can
    # seed a random number generator with it.
    generators = []
    for i in range(CLIENTS):
        tries = 0
        while True:
            tries += 1
            candidate = Rand.randrange(1 << (P.bit_length() - 1), P)
            if pow(candidate, 2, P) != 1 and pow(candidate, Q, P) == 1:
                generators.append(candidate)
                break
    ac = AuthenticationContext(client_pub_keys, server_pub_keys, server_randomness, generators)

    # Now, with that out of the way, let's do some authentication!
    state = clients[3].prepare_client_auth_request(ac)
    clients[3].prepare_client_challenge_request(state)
    # We use a bogus challenge for now. The challenge needs to be distributed
    # among the servers. David, give us some distributed randomness!
    challenge = Challenge(Rand.randrange(Q), state.T)
    clients[3].answer_server_challenge(state, challenge.C)
    # Begin verification.
    msg_chain = VerificationChain(challenge, state.ephemeral_public_key, state.commitments, state.initial_linkage_tag, state.proof)
    try:
        for s in servers:
            s.authenticate_client(ac, msg_chain)
    except DishonestClient as e:
        ac.verify_dishonest_client_proof(e.proof)
        last_commit = state.commitments[e.proof.server - 1] if e.proof.server >= 1 else G
        assert pow(last_commit, e.proof.shared_secret, P) != state.commitments[e.proof.server]
        print("Verified dishonest client proof.")
    else:
        print("Authentication succeeded.")
        print("checking linkage tag...", end=" ")
        s = 1
        for server in servers:
            s *= server.secret
            s %= Q
        if msg_chain.server_proofs[-1].T == pow(ac.generators[3], s, P):
            print("Looks okay!")
        else:
            print("Linkage tag not generated correctly!")

if __name__ == "__main__":
    example()
