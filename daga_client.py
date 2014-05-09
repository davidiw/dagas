import argparse
import json
import random
import requests
import sys

from urllib.parse import urlparse

import daga


def main():
    p = argparse.ArgumentParser(description="Authenticate with DAGA")
    p.add_argument("-a", "--auth_context", required=True,
                   help="The path to the authentication context folder")
    p.add_argument("-p", "--private_data", required=True,
                   help="Path to the servers private data")
    p.add_argument("-s", "--server_list", help="List of servers uris")
    opts = p.parse_args()

    with open(opts.auth_context, "r", encoding="utf-8") as fp:
        ac_data = json.load(fp)
        uuid = ac_data["uuid"]
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
        client = daga.Client(p_data["n"], p_data["private_key"])

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

    state = client.prepare_client_auth_request(ac)
    client.prepare_client_challenge_request(state)
    d = {
        "uuid" : uuid,
        "ephemeral_public_key" : state.ephemeral_public_key,
        "initial_linkage_tag" : state.initial_linkage_tag,
        "commitments" : state.commitments,
        "T" : state.T,
    }
    resp = requests.post("http://" + server.netloc + "/request_challenge",
                         headers={"content-type" : "application/json"},
                         data=json.dumps(d)).json()
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
    resp = requests.post("http://" + server.hostname + ":" + str(server.port) + "/authenticate",
                         headers={"content-type" : "application/json"},
                         data=json.dumps(d)).json()
    tag = resp["tag"]
    for pub, tag_sig in zip(ac.server_keys, resp["tag_sigs"]):
        daga.dsa_verify(pub, tag, tag_sig)
    print("Well, that seemed to work.")

if __name__ == "__main__":
    main()
