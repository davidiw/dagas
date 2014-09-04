import argparse
import json
import random
import requests
import sys
import time

from hashlib import sha512
from urllib.parse import urlparse

import daga

ltime = time.time()
bench = False
def benchmark():
    if not bench:
        pass

    ctime = time.time()
    global ltime
    print(ctime - ltime)
    ltime = ctime

def main():
    start = time.time()
    p = argparse.ArgumentParser(description="Authenticate with DAGA")
    p.add_argument("-a", "--auth_context", required=True,
                   help="The path to the authentication context folder")
    p.add_argument("-p", "--private_data", required=True,
                   help="Path to the servers private data")
    p.add_argument("-s", "--server_list", help="List of servers uris",
                   required=True)
    p.add_argument("-b", "--benchmark", help="Enable benchmarking",
                   dest="bench", action="store_true")
    opts = p.parse_args()

    global bench
    bench = opts.bench

    with open(opts.auth_context, "r", encoding="utf-8") as fp:
        ac_data = json.load(fp)
    uuid = ac_data["uuid"]
    ac = daga.AuthenticationContext(
        ac_data["client_public_keys"],
        ac_data["server_public_keys"],
        ac_data["server_randomness"],
        ac_data["generators"]
    )

    h = sha512()
    h.update(json.dumps(ac_data["uuid"]).encode("utf-8"))
    h.update(json.dumps(ac_data["client_public_keys"]).encode("utf-8"))
    h.update(json.dumps(ac_data["server_public_keys"]).encode("utf-8"))
    h.update(json.dumps(ac_data["generators"]).encode("utf-8"))
    h.update(json.dumps(ac_data["group_generator"]).encode("utf-8"))
    acs = h.digest()

    for key, signature in zip(ac.server_keys, ac_data["signatures"]):
        daga.dsa_verify(key, acs, signature)

    with open(opts.private_data, "r", encoding="utf-8") as fp:
        p_data = json.load(fp)
        if p_data["uuid"] != uuid:
            print("Client UUID doesn't match.", file=sys.stderr)
            sys.exit(1)
        client = daga.Client(p_data["n"], p_data["private_key"])

    with open(opts.server_list, "r", encoding="utf-8") as fp:
        server_list = json.load(fp)

    server_index = random.randint(0, len(server_list) - 1)
    assert len(server_list) <= len(ac.server_keys)
    server = urlparse(server_list[str(server_index)])
    assert server.hostname != None
    assert server.port != None

    state = client.prepare_client_auth_request(ac)
    client.prepare_client_challenge_request(state)
    d = {
        "uuid" : uuid,
        "ephemeral_public_key" : state.ephemeral_public_key,
        "initial_linkage_tag" : state.initial_linkage_tag,
        "commitments" : state.commitments,
        "T" : state.T,
    }

    benchmark()

    resp = requests.post("http://" + server.netloc + "/request_challenge",
                         headers={"content-type" : "application/json"},
                         data=json.dumps(d)).json()

    benchmark()

    auth_id = resp["auth_id"]
    challenge = resp["challenge"]
    for pub, sig in zip(ac.server_keys, resp["sigs"]):
        daga.dsa_verify(pub, challenge, sig)
    client.answer_server_challenge(state, challenge)
    d = {
        "auth_id" : resp["auth_id"],
        "C" : state.proof.C,
        "R" : state.proof.R,
    }

    benchmark()
    start = time.time()

    resp = requests.post("http://" + server.hostname + ":" + str(server.port) + "/authenticate",
                         headers={"content-type" : "application/json"},
                         data=json.dumps(d)).json()

    benchmark()

    tag = resp["tag"]
    for pub, tag_sig in zip(ac.server_keys, resp["tag_sigs"]):
        daga.dsa_verify(pub, tag, tag_sig)

    benchmark()

if __name__ == "__main__":
    main()
