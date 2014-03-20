import argparse
import json
import requests
import sys

import daga


def main():
    p = argparse.ArgumentParser(description="Authenticate with DAGA")
    p.add_argument("auth_context")
    p.add_argument("private_data")
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

    server_host = "localhost:12345"
    state = client.prepare_client_auth_request(ac)
    client.prepare_client_challenge_request(state)
    d = {
        "uuid" : uuid,
        "ephemeral_public_key" : state.ephemeral_public_key,
        "initial_linkage_tag" : state.initial_linkage_tag,
        "commitments" : state.commitments,
        "T" : state.T,
    }
    resp = requests.post("http://" + server_host + "/request_challenge",
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
        "bind" : 42,
    }
    resp = requests.post("http://" + server_host + "/authenticate",
                         headers={"content-type" : "application/json"},
                         data=json.dumps(d)).json()
    tag = resp["tag"]
    for pub, tag_sig, bind_sig in zip(ac.server_keys, resp["tag_sigs"], resp["binding_sigs"]):
        daga.dsa_verify(pub, tag, tag_sig)
        daga.dsa_verify(pub, 42, bind_sig)
    print("Well, that seemed to work.")

if __name__ == "__main__":
    main()
