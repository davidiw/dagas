import argparse
import json
import os
import time
import signal
import subprocess
import sys


def main():
    p = argparse.ArgumentParser(description="Run some DAGA servers")
    p.add_argument("context_dir")
    opts = p.parse_args()

    ac_file = os.path.join(opts.context_dir, "context.json")
    with open(ac_file, "r", encoding="utf-8") as fp:
        n_servers = len(json.load(fp)["server_public_keys"])

    print("Launching {} servers".format(n_servers))
    try:
        procs = []
        for i in range(n_servers):
            priv_file = os.path.join(opts.context_dir, "server-{}.json".format(i))
            p = subprocess.Popen([sys.executable, "dagad.py", ac_file, priv_file],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            procs.append(p)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    print("Cleaning up")
    for i, p in enumerate(procs):
        p.wait()
        print("Server {}".format(i))
        print("-"*200)
        print(p.stderr.read().decode("utf-8"))
        print("-"*200)

if __name__ == "__main__":
    main()
