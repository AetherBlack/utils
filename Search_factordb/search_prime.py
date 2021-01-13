#!/usr/bin/python3

from bs4 import BeautifulSoup

import requests
import sys

# Static
URL = "http://factordb.com/index.php?query={0}"

# Function
def _help():
    print(f"[#] {sys.argv[0]} number")
    exit(1)

# Check the length of argv
if len(sys.argv) != 2:
    _help()

number = sys.argv[1]

# Check if number is a decimal
if not number.isdecimal():
    _help()

# Get the response
res = requests.get(URL.format(number)).text

# Parse
soup = BeautifulSoup(res, "html.parser")

# Get the status of the prime number
status = soup.html.body.findAll("table")[1].findAll("td")[4].string

# Get all primes
primes = str(soup.html.body.findAll("table")[1].findAll("td")[6])

# Delete garbage tag
while "<" in primes and ">" in primes:
    tmp = [primes.find("<"), primes.find(">") + 1]
    primes = primes.replace(primes[tmp[0] : tmp[1]], "")

print(f"[+] {status}: {primes}")