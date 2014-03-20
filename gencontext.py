import argparse
import json
import os
import random
import shutil
import uuid

from daga import G, P, Q

def random_dh_key():
    # The secret should be the same bit length as P.
    return random.randrange(1 << (P.bit_length() - 1), P - 1)

def main():
    p = argparse.ArgumentParser(description="Generate a DAGA auth context")
    p.add_argument("-c", "--clients", type=int, metavar="N", default=32, dest="n_clients")
    p.add_argument("-s", "--servers", type=int, metavar="N", default=3, dest="n_servers")
    p.add_argument("output_dir")
    opts = p.parse_args()
    print("Generating context with {} clients and {} servers.".format(opts.n_clients, opts.n_servers))

    shutil.rmtree(opts.output_dir, True)
    os.mkdir(opts.output_dir)

    client_priv_keys = [random_dh_key() for i in range(opts.n_clients)]
    client_pub_keys = [pow(G, key, P) for key in client_priv_keys]
    server_priv_keys = [random_dh_key() for i in range(opts.n_servers)]
    server_pub_keys = [pow(G, key, P) for key in server_priv_keys]
    server_secrets = [random.randrange(1, Q) for i in range(opts.n_servers)]
    server_randomness = [pow(G, s, P) for s in server_secrets]
    generators = []
    for i in range(opts.n_clients):
        tries = 0
        while True:
            tries += 1
            candidate = random.randrange(1 << (P.bit_length() - 1), P)
            if pow(candidate, 2, P) != 1 and pow(candidate, Q, P) == 1:
                generators.append(candidate)
                break
    iden = str(uuid.uuid4())
    ac = {
        "uuid" : iden,
        "client_public_keys" : client_pub_keys,
        "server_public_keys" : server_pub_keys,
        "server_randomness" : server_randomness,
        "generators" : generators,
    }
    with open(os.path.join(opts.output_dir, "context.json"), "w", encoding="utf-8") as fp:
        json.dump(ac, fp)
    for i, key in enumerate(client_priv_keys):
        with open(os.path.join(opts.output_dir, "client-{}.json".format(i)), "w", encoding="utf-8") as fp:
            json.dump({"uuid" : iden, "n" : i, "private_key" : key}, fp)
    for i, (key, secret) in enumerate(zip(server_priv_keys, server_secrets)):
        with open(os.path.join(opts.output_dir, "server-{}.json".format(i)), "w", encoding="utf-8") as fp:
            json.dump({"uuid" : iden, "n" : i, "private_key" : key, "secret" : secret}, fp)

    print("Congratulations, you are now the owner of an authentication context with UUID {}.".format(iden))

if __name__ == "__main__":
    main()
