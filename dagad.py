#!/usr/bin/env python3
"""DAGA Server"""

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

    def __init__(self, auth_context, server, servers):
        self.ac = auth_context
        self.server = server
        self.servers = servers
        self.bindings = {}

class GlobalState:

    def __init__(self, contexts):
        self.contexts = contexts
        self.pool = multiprocessing.Pool()
        self.active_auths = {}

def _internal_begin_challenge_generation(d):
    state.active_auths[d["auth_id"]] = d["client_data"]
    context = state.contexts[d["client_data"]["uuid"]]
    part = daga.Rand.randrange(daga.Q)
    return {
        "n" : part,
        "sig" : daga.dsa_sign(context.server.private_key, part),
    }

@route("/internal/begin_challenge_generation", method="POST")
def internal_begin_challenge_generation():
    return _internal_begin_challenge_generation(request.json)

def _internal_finish_challenge_generation(d):
    context = state.contexts[state.active_auths[d["auth_id"]]["uuid"]]
    challenge = 0
    for pub, (part, sig) in zip(context.ac.server_keys, d["parts"]):
        daga.dsa_verify(pub, part, sig)
        challenge += part
    challenge %= daga.Q
    state.active_auths[d["auth_id"]]["challenge"] = challenge
    return {
        "challenge" : challenge,
        "sig" : daga.dsa_sign(context.server.private_key, challenge),
    }

@route("/internal/finish_challenge_generation", method="POST")
def internal_finish_challenge_generation():
    return _internal_finish_challenge_generation(request.json)

def _internal_check_challenge_response(d):
    auth_ctx = state.active_auths[d["auth_id"]]
    context = state.contexts[auth_ctx["uuid"]]
    client_proof = daga.ClientProof(d["C"], d["R"])
    auth_ctx["C"] = d["C"]
    auth_ctx["R"] = d["R"]
    msg_chain = daga.VerificationChain(daga.Challenge(auth_ctx["challenge"], auth_ctx["T"]),
                                       auth_ctx["ephemeral_public_key"],
                                       auth_ctx["commitments"],
                                       auth_ctx["initial_linkage_tag"],
                                       client_proof)
    msg_chain.server_proofs = [daga.ServerProof(*x) for x in d["server_proofs"]]
    msg_chain = state.pool.apply(context.server.authenticate_client, [context.ac, msg_chain])
    sp = msg_chain.server_proofs[-1]
    return {"proof" : (sp.T, sp.c, sp.r1, sp.r2)}

@route("/internal/check_challenge_response", method="POST")
def internal_check_challenge_response():
    return _internal_check_challenge_response(request.json)

def _internal_bind_linkage_tag(d):
    auth_ctx = state.active_auths[d["auth_id"]]
    context = state.contexts[auth_ctx["uuid"]]
    client_proof = daga.ClientProof(auth_ctx["C"], auth_ctx["R"])
    msg_chain = daga.VerificationChain(daga.Challenge(auth_ctx["challenge"], auth_ctx["T"]),
                                       auth_ctx["ephemeral_public_key"],
                                       auth_ctx["commitments"],
                                       auth_ctx["initial_linkage_tag"],
                                       client_proof)
    msg_chain.server_proofs = [daga.ServerProof(*x) for x in d["server_proofs"]]
    # Verify everyone.
    for i in range(len(context.ac.server_keys)):
        assert state.pool.apply(msg_chain.check_server_proof, [context.ac, i])
    linkage_tag = msg_chain.server_proofs[-1].T
    context.bindings[linkage_tag] = auth_ctx["ephemeral_public_key"]
    return {
        "tag" : linkage_tag,
        "tag_sig" : daga.dsa_sign(context.server.private_key, linkage_tag)
    }

@route("/internal/bind_linkage_tag", method="POST")
def internal_bind_linkage_tag():
    return _internal_bind_linkage_tag(request.json)

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
    sig = daga.dsa_sign(context.server.private_key, key_hash.encode("utf-8"))
    return {
        "sig" : sig,
        "key_hash" : key_hash
    }

def internal_call(ctx, srv, name, data):
    if srv == ctx.server.id:
        return globals()["_internal_" + name](data)
    return requests.post("http://{}:{}/internal/{}".format(
                         ctx.servers[srv].hostname,
                         ctx.servers[srv].port, name),
                         headers={"content-type" : "application/json"},
                         data=json.dumps(data)).json()

@route("/request_challenge", method="POST")
def request_challenge():
    client_data = request.json
    context = state.contexts[client_data["uuid"]]
    auth_id = str(uuid.uuid4())
    r = {
        "auth_id" : auth_id,
        "client_data" : client_data,
    }
    challenge_parts = []
    for i in range(len(context.ac.server_keys)):
        d = internal_call(context, i, "begin_challenge_generation", r)
        challenge_parts.append((d["n"], d["sig"]))
    r = {
        "auth_id" : auth_id,
        "parts" : challenge_parts,
    }
    sigs = []
    for i in range(len(context.ac.server_keys)):
        d = internal_call(context, i, "finish_challenge_generation", r)
        challenge = d["challenge"]
        sigs.append(d["sig"])
    return {"auth_id" : auth_id, "challenge" : challenge, "sigs" : sigs}

@route("/authenticate", method="POST")
def authenticate():
    client_data = request.json
    auth_ctx = state.active_auths[client_data["auth_id"]]
    context = state.contexts[auth_ctx["uuid"]]
    proofs = []
    r = {
        "auth_id" : client_data["auth_id"],
        "C" : client_data["C"],
        "R" : client_data["R"],
        "server_proofs" : proofs, # Will be mutated.
    }
    for i in range(len(context.ac.server_keys)):
        d = internal_call(context, i, "check_challenge_response", r)
        proofs.append(d["proof"])
    r = {
        "auth_id" : client_data["auth_id"],
        "server_proofs" : proofs,
    }
    sigs = []
    for i in range(len(context.ac.server_keys)):
        d = internal_call(context, i, "bind_linkage_tag", r)
        tag = d["tag"]
        sigs.append(d["tag_sig"])
    return {
        "tag" : tag,
        "tag_sigs" : sigs,
    }

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

    p = argparse.ArgumentParser(description="Generate a DAGA auth context")
    p.add_argument("-a", "--auth_context", required=True,
                   help="The path to the authentication context folder")
    p.add_argument("-p", "--private_data", required=True,
                   help="Path to the servers private data")
    p.add_argument("-s", "--server_list", help="List of servers uris",
                   required=True)
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
        server = daga.Server(priv_data["n"], priv_data["private_key"], priv_data["secret"])

    with open(opts.server_list, "r", encoding="utf-8") as fp:
        server_dict = json.load(fp)
    servers = []

    assert len(server_dict) <= len(ac.server_keys)
    for i in range(len(ac.server_keys)):
        uri = urlparse(server_dict[str(i)])
        assert uri.hostname != None
        assert uri.port != None
        servers.append(uri)

    state = GlobalState({uuid : Context(ac, server, servers)})

    uri = servers[server.id]
    run(server=Server, host=uri.hostname, port=uri.port)

if __name__ == "__main__":
    main()
