import argparse
import json
import random
import requests
import sys

from urllib.parse import urlparse

import daga


def main():
    p = argparse.ArgumentParser(description="Authenticate with LRS")
    p.add_argument("-a", "--auth_context", required=True,
                   help="The path to the authentication context folder")
    p.add_argument("-p", "--private_data", required=True,
                   help="Path to the servers private data")
    p.add_argument("-s", "--server_list", help="List of servers uris")
    opts = p.parse_args()

    with open(opts.auth_context, "r", encoding="utf-8") as fp:
        ac_data = json.load(fp)
        uuid = ac_data["uuid"]
        group_gen = ac_data["group_generator"]
        ac = daga.AuthenticationContext(
            ac_data["client_public_keys"],
            ac_data["server_public_keys"],
            ac_data["server_randomness"],
            ac_data["generators"]
        )

    with open(opts.private_data, "r", encoding="utf-8") as fp:
        p_data = json.load(fp)
        if p_data["uuid"] != uuid:
            print("Client UUID doesn't match.", file=sys.stderr)
            sys.exit(1)
        priv_key = p_data["private_key"]
        index = p_data["n"]

    server_index = random.randint(0, len(ac.server_keys) - 1)
    if opts.server_list != None:
        with open(opts.server_list, "r", encoding="utf-8") as fp:
            server_list = json.load(fp)
            assert len(server_list) == len(ac.server_keys)
            server = urlparse(server_list[str(server_index)])
            assert server.hostname != None
            assert server.port != None
    else:
        server = urlparse("http://localhost:" + str(12345 + server_index))

    eph_priv_key = daga.random_dh_key()
    eph_pub_key = pow(daga.G, priv_key, daga.P)
    sig = daga.dsa_sign(priv_key, eph_pub_key)

    d = {
        "uuid" : uuid,
        "pub_key" : eph_pub_key,
        "index" : index,
        "sig" : sig,
    }
    resp = requests.post("http://" + server.netloc + "/submit_key",
                         headers={"content-type" : "application/json"},
                         data=json.dumps(d)).json()
    assert resp
    print("Well, that seemed to work.")

if __name__ == "__main__":
    main()
