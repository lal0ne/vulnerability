import re
import urllib3
import requests
import concurrent.futures
from distutils.version import LooseVersion
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
urllib3.disable_warnings()

GREEN = "\033[92m"
RESET = "\033[0m"

exploit_header = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
}
maybeExploitFile = open("maybe-exploit.txt", "a+", encoding="utf-8")

def checkVersion(url):
    try:
        response = requests.get(url=url + "/Login?Reason=0", headers=exploit_header, verify=False)
        serverString = response.headers["Server"]
        version = re.search(r"ScreenConnect\/([\d\.]+)-\d+", serverString).group(1)
        if LooseVersion(version) <= LooseVersion("23.9.7"):
            maybeExploitFile.write(url + "\n")
            print(f"[+] Version: {version} <= 23.9.7. There may be a vulnerability in {url}")
        else:
            pass
    except:
        pass

def main():
    with open("urls.txt", "r") as file:
        urls = [line.strip() for line in file.readlines()]
    max_workers = 100
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(checkVersion, urls)

if __name__ == "__main__":
    main()
    maybeExploitFile.close()