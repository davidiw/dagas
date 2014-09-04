import argparse
import json
import random
import requests
import sys
import time

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
    p = argparse.ArgumentParser(description="Authenticate with LRS")
    p.add_argument("-a", "--auth_context", required=True,
                   help="The path to the authentication context folder")
    p.add_argument("-p", "--private_data",
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
        server_len = len(ac_data["server_public_keys"])

    with open(opts.server_list, "r", encoding="utf-8") as fp:
        server_list = json.load(fp)

    server_index = random.randint(0, len(server_list) - 1)
    assert len(server_list) <= server_len
    server = urlparse(server_list[str(server_index)])
    assert server.hostname != None
    assert server.port != None

    priv_key = daga.random_dh_key()
    pub_key = pow(daga.G, priv_key, daga.P)

    d = {
        "uuid" : uuid,
        "pub_key" : pub_key,
    }

    benchmark()

    resp = requests.post("http://" + server.netloc + "/submit_key",
                         headers={"content-type" : "application/json"},
                         data=json.dumps(d)).json()
    assert resp
    benchmark()

if __name__ == "__main__":
    main()
