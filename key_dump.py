import argparse
import json
import random
import requests
import sys

from hashlib import sha512
from urllib.parse import urlparse

import daga

def main():
    p = argparse.ArgumentParser(description="Authenticate with DAGA")
    p.add_argument("-a", "--auth_context", required=True,
                   help="The path to the authentication context folder")
    p.add_argument("-s", "--server_list", help="List of servers uris",
                   required=True)
    p.add_argument("-o", "--output", help="Write the dump to a file")
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

    with open(opts.server_list, "r", encoding="utf-8") as fp:
        server_list = json.load(fp)

    server_index = random.randint(0, len(server_list) - 1)
    assert len(server_list) <= len(ac.server_keys)
    server = urlparse(server_list[str(server_index)])
    assert server.hostname != None
    assert server.port != None

    d = { "uuid" : uuid }
    resp = requests.post("http://" + server.netloc + "/dump_keys",
                         headers={"content-type" : "application/json"},
                         data=json.dumps(uuid)).json()

    b_ks = list(resp["keys"])
    b_ks.sort()
    h = sha512()
    for key in b_ks:
        h.update(daga.elem_to_bytes(key))
    key_hash = h.hexdigest()
    key_hash = key_hash.encode("utf-8")

    for pub, key_sig in zip(ac.server_keys, resp["key_sigs"]):
        daga.dsa_verify(pub, key_hash, key_sig)

    if opts.output:
        with open(opts.output, "w+", encoding = ("utf-8")) as fp:
            json.dump(resp, fp)


if __name__ == "__main__":
    main()
