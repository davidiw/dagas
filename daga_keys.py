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
    p.add_argument("-o", "--output", required=True,
                   help="Destination for keys")
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

    server = urlparse("http://localhost:12345")
    resp = requests.post("http://" + server.netloc + "/dump_keys",
                         headers={"content-type" : "application/json"},
                         data=json.dumps(uuid)).json()

    with open(opts.output, "w", encoding="utf-8") as fp:
        json.dump(resp, fp)

if __name__ == "__main__":
    main()
