#!/usr/bin/python3

from bs4 import BeautifulSoup

import requests
import sys

#URL of man page
URL = "https://www.aldeid.com/wiki/X86-assembly/Instructions/{0}"

class AsmInstruction:

    def __init__(self, content, text_list):
        self.content = content
        self.text_list = text_list

    def get_content(self, title, stop_value, value2replace="", replace2value="", next_title=None):

        #Check examples
        if title in self.content:

            #Get the examples
            actual_title = str()
            title_content = str()
            index = 0

            #Get index of the content for the given title
            while actual_title != title:
                actual_title = self.text_list[index]
                index += 1

            #Get the content
            while self.text_list[index] != stop_value and self.text_list[index] != next_title:
                #Add text
                title_content += self.text_list[index] + "\n"
                index += 1

            #Print
            print(f"{title} :")
            print("-" * (len(title) + 2))
            print(title_content.replace(value2replace, replace2value))
            print()

#Check for asm_instruction in args
if len(sys.argv) != 2:
    print(f"{sys.argv[0]} [asm instruction]")
    exit(1)

#Get the asm_instruction
asm_instruction = sys.argv[1]

#Requests
res = requests.get(URL.format(asm_instruction))

#Check the status code
if res.status_code == 200:
    #Parse response
    soup = BeautifulSoup(res.text, "html.parser")

    #Get each line
    text_list = soup.get_text().split("\n")

    #Get instance
    asm = AsmInstruction(res.text, text_list)

    #Print content
    asm.get_content("Description", "", next_title="Syntax")
    asm.get_content("Syntax", "", next_title="Examples")
    asm.get_content("Examples", "Comments")

    exit(0)

else:
    #Error and quit
    print(f"[*] '{asm_instruction}' Not found ! ")
    exit(1)