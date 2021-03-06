#!/usr/bin/env python3
"""PSK Server"""

import argparse
import json
import multiprocessing
import ssl
import sys
import uuid

import requests

from hashlib import sha512
from urllib.parse import urlparse
from bottle import request, route, run

import daga
from server import Server

class Context:

    def __init__(self, auth_context, server_id, server_key, servers):
        self.ac = auth_context
        self.server_id = server_id
        self.server_key = server_key
        self.servers = servers
        self.bindings = {}

class GlobalState:

    def __init__(self, contexts):
        self.contexts = contexts
        self.pool = multiprocessing.Pool()

@route("/internal/sign_keys", method="POST")
def internal_sign_keys():
    return _internal_sign_keys(request.json)

def _internal_sign_keys(d):
    context = state.contexts[d]
    b_ks = list(context.bindings.keys())
    b_ks.sort()
    h = sha512()
    for b_k in b_ks:
        key = context.bindings[b_k]
        h.update(daga.elem_to_bytes(key))
    key_hash = h.hexdigest()
    sig = daga.dsa_sign(context.server_key, key_hash.encode("utf-8"))
    return {
        "sig" : sig,
        "key_hash" : key_hash
    }

@route("/internal/submit_key", method="POST")
def internal_submit_key():
    client_data = request.json
    context = state.contexts[client_data["uuid"]]
    sig = client_data["sig"]
    pub_key = client_data["pub_key"]
    client_index = client_data["index"]
    daga.dsa_verify(context.ac.client_keys[client_index], pub_key, sig)
    context.bindings[client_index] = pub_key
    return {"result": "True"}

def internal_call(ctx, srv, name, data):
    if srv == ctx.server_id:
        return globals()["_internal_" + name](data)
    return requests.post("http://{}:{}/internal/{}".format(
                         ctx.servers[srv].hostname,
                         ctx.servers[srv].port, name),
                         headers={"content-type" : "application/json"},
                         data=json.dumps(data)).json()

@route("/submit_key", method="POST")
def submit_key():
    client_data = request.json
    context = state.contexts[client_data["uuid"]]
    sig = client_data["sig"]
    pub_key = client_data["pub_key"]
    client_index = client_data["index"]
    daga.dsa_verify(context.ac.client_keys[client_index], pub_key, sig)
    for srv in range(len(context.servers)):
        if srv == context.server_id:
            continue
        requests.post("http://{}:{}/internal/{}".format(
                             context.servers[srv].hostname,
                             context.servers[srv].port, "submit_key"),
                             headers={"content-type" : "application/json"},
                             data=json.dumps(client_data)).json()
    context.bindings[client_index] = pub_key
    return {"result" : "True"}

@route("/dump_keys", method="POST")
def dump_keys():
    c_uuid = request.json
    context = state.contexts[c_uuid]

    key_sigs = []
    expected_key_hash = None
    for i in range(len(context.ac.server_keys)):
        d = internal_call(context, i, "sign_keys", c_uuid)
        sig = d["sig"]
        key_hash = d["key_hash"].encode("utf-8")
        if expected_key_hash == None:
            expected_key_hash = key_hash
        else:
            assert key_hash == expected_key_hash
        daga.dsa_verify(context.ac.server_keys[i], key_hash, sig)
        key_sigs.append(sig)
    return {
        "keys" : list(context.bindings.values()),
        "key_sigs" : key_sigs
    }

def main():
    global state

    p = argparse.ArgumentParser(description="Start a PSK Server")
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
        priv_data = json.load(fp)
        server_key = priv_data["private_key"]
        server_id = priv_data["n"]

    with open(opts.server_list, "r", encoding="utf-8") as fp:
        server_dict = json.load(fp)
    servers = []

    assert len(server_dict) <= len(ac.server_keys)
    for i in range(len(ac.server_keys)):
        uri = urlparse(server_dict[str(i)])
        assert uri.hostname != None
        assert uri.port != None
        servers.append(uri)

    state = GlobalState({uuid : Context(ac, server_id, server_key, servers)})

    uri = servers[server_id]
    run(server=Server, host=uri.hostname, port=uri.port)

if __name__ == "__main__":
    main()
