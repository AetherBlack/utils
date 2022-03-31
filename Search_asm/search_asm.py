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
            print("".ljust(len(title) + 2, "-"))
            print(title_content.replace(value2replace, replace2value))
            print()
    
    @staticmethod
    def register() -> str:
        return """+-----+------+------+----+------+
| 64  | 32   | 16   | 8h | 8l   |
+-----+------+------+----+------+
| rax | eax  | ax   | ah | al   |
| rbx | ebx  | bx   | bh | bl   |
| rcx | ecx  | cx   | ch | cl   |
| rdx | edx  | dx   | dh | dl   |
| rsi | esi  | si   |    | sil  |
| rdi | esi  | di   |    | dil  |
| rbp | ebp  | bp   |    | bpl  |
| rsp | esp  | sp   |    | spl  |
| r8  | r8d  | r8w  |    | r8b  |
| r9  | r9d  | r9w  |    | r9b  |
| r10 | r10d | r10w |    | r10b |
| r11 | r11d | r11w |    | r11b |
| r12 | r12d | r12w |    | r12b |
| r13 | r13d | r13w |    | r13b |
| r14 | r14d | r14w |    | r14b |
| r15 | r15d | r15w |    | r15b |
+-----+------+------+----+------+"""

    @staticmethod
    def help() -> None:
        print(f"{sys.argv[0]} [asm instruction]")
        print(f"{sys.argv[0]} --registers: Print table of register")
        print(f"{sys.argv[0]} --help: Print this message")

#Check for asm_instruction in args
if len(sys.argv) != 2:
    AsmInstruction.help()
    exit(1)

#Get the asm_instruction
asm_instruction = sys.argv[1]

# Check command arguments
if asm_instruction == "--registers":
    print(AsmInstruction.register())
    exit(0)
elif asm_instruction == "--help":
    AsmInstruction.help()
    exit(0)

#Requests
res = requests.get(URL.format(asm_instruction))

#Check the status code
if res.status_code == 200:
    #Parse response
    soup = BeautifulSoup(res.text, "html.parser")

    #Get each line
    text_list = soup.get_text().splitlines()

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