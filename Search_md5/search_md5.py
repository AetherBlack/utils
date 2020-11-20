#!/usr/bin/python3.8

from bs4 import BeautifulSoup

import requests
import sys

# CONST
URL = "https://md5.gromweb.com/?md5={0}"

#Check the number of args
if len(sys.argv) != 2:
    print(f"{sys.argv[0]} md5")
    exit(1)

#Get the second arg
md5 = sys.argv[1]

#Check the length of the md5
if len(md5) != 32:
    print(f"[!] MD5 length must be 32 instead of {len(md5)}")
    exit(1)


#Send requests
res = requests.get(URL.format(md5))

#Check status code
if res.status_code == 200:
    #Get text
    res = res.text

    #Parse result
    soup = BeautifulSoup(res, features="html.parser")

    #Get the value
    reversed_value = soup.findAll("input")[2].get("value")

    #Check the value
    if reversed_value == "":
        print("[*] Not Found !")
        exit(7)
    else:
        print(f"[*] Reversed : {reversed_value}")
        exit(0)
#Else prompt error
else:
    print(f"[!] Error status code : {res.status_code}")
    exit(1)
    