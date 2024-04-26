#!/usr/bin/env python3

from glob import glob
import argparse
import os
import sys


def main():
    parser = argparse.ArgumentParser(description="Evaluate if the CrushFTP File Read vulnerability was exploited")
    parser.add_argument("dir", type=str, help="Path to CrushFTP installation directory")
    args = parser.parse_args()

    if not os.path.exists(os.path.join(args.dir, "CrushFTP.jar")):
        print(f"[!] The following directory does not look like a CrushFTP installation folder: {args.dir}")
        return 1
    
    log_files = [os.path.join(args.dir, "CrushFTP.log")] + glob(os.path.join(args.dir, "logs", "session_logs", "*", "session_HTTP_*.log")) + glob(os.path.join(args.dir, "logs", "CrushFTP.log*"))

    for fname in log_files:
        with open(fname, "r") as f:
            txt = f.read()

        if "<INCLUDE>" in txt:
            lines = [l for l in txt.split("\n") if "<INCLUDE>" in l]

            for l in lines:
                try:
                    ip = l.split("|")[2].split(":")[3].split("]")[0]
                    print(f"{fname}: traces of exploitation by {ip}")
                except IndexError:
                    print(f"{fname}: traces of exploitation")
            else:
                print(f"{fname}: traces of exploitation")


if __name__ == "__main__":
    sys.exit(main() or 0)
