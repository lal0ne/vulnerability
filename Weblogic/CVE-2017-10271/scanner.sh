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



