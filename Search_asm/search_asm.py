#!/usr/bin/python3

from bs4 import BeautifulSoup

import requests
import sys

# URL of man page
URL = "https://www.aldeid.com/wiki/X86-assembly/Instructions/{0}"
PAGE_TAGS = ["h1", "p", "ul", "dl", "h2", "pre"]

class AsmInstruction:

    def __init__(self):
        """
        Assembly Instruction class
        """

    @staticmethod
    def print_assembly_manual(page_content: BeautifulSoup) -> None:
        """
        Print to the stdout the content of the page.
        """
        tags = page_content.find_all(PAGE_TAGS)

        # Get the first title
        for index, tag in enumerate(tags):
            if "h1" in str(tag):
                break
        
        # Print page content
        for tag in tags[index:]:
            # Get string without tags
            value = "".join(tag.strings)

            # If comments stop
            if value == "Comments": break

            # Print value
            print(value)
            # If it's a title, print a line to split with the text
            if "h1" in str(tag):
                print("".ljust(len(value), "-"))
    
    @staticmethod
    def register() -> str:
        """
        Return the table of register.
        """
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
        """
        Print arguments for the script.
        """
        script_name = sys.argv.pop(0)
        print(f"{script_name} [asm instruction]")
        print(f"{script_name} --registers: Print table of register")
        print(f"{script_name} --help: Print this message")


if __name__ == "__main__":
    # Check for asm_instruction in args
    if len(sys.argv) != 2:
        AsmInstruction.help()
        exit(1)

    # Get the asm_instruction
    asm_instruction = sys.argv[1]

    # Check command arguments
    if asm_instruction == "--registers":
        print(AsmInstruction.register())
        exit(0)
    elif asm_instruction == "--help":
        AsmInstruction.help()
        exit(0)

    # Get the content of the page
    res = requests.get(
            URL.format(asm_instruction),
            headers={"User-Agent": "Mozilla/5.0"}
        )

    # Check the status code
    if res.status_code == 200:
        # Parse response
        soup = BeautifulSoup(res.text, "html.parser")

        # Get each line
        parser_content = soup.find("div", {"class": "mw-parser-output"})

        # Print content of the assembly instruction manual
        AsmInstruction.print_assembly_manual(parser_content)
        exit(0)

    else:
        #Error and quit
        print(f"[*] '{asm_instruction}' Not found ! ")
        exit(1)
