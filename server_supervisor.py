import argparse
import json
import os
import time
import signal
import subprocess
import sys


def main():
    p = argparse.ArgumentParser(description="Run some DAGA servers")
    p.add_argument("-c", "--context_dir", required=True)
    p.add_argument("-a", "--auth_engine")
    opts = p.parse_args()

    app = "dagad.py"
    if opts.auth_engine != None:
        app = opts.auth_engine

    ac_file = os.path.join(opts.context_dir, "context.json")
    with open(ac_file, "r", encoding="utf-8") as fp:
        n_servers = len(json.load(fp)["server_public_keys"])

    print("Launching {} servers".format(n_servers))
    try:
        procs = []
        for i in range(n_servers):
            priv_file = os.path.join(opts.context_dir, "server-{}.json".format(i))
            p = subprocess.Popen([sys.executable, app, "-a", ac_file, "-p", priv_file],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            procs.append(p)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    print("Cleaning up")
    for i, p in enumerate(procs):
        # This is overkill but it  seems difficult to kindly kill of the pool
        p.kill()
        p.wait()
        print("Server {}".format(i))
        print("-"*100)
        print(p.stdout.read().decode("utf-8"))
        print("-"*100)
        print(p.stderr.read().decode("utf-8"))
        print("-"*100)

if __name__ == "__main__":
    main()
