
from impacket.examples.ldap_shell import LdapShell

import sys

from krbldapshell.network.LDAP import LDAP
from krbldapshell.core.Logger import Logger

class DomainDumper:

    def __init__(self, ldap: LDAP) -> None:
        self.root = ldap.defaultNamingContext
    
    def domainDump(self) -> None:
        print("Not today :(")

class FakeTcpClient:

    stdin = sys.stdin
    stdout = sys.stdout

    def __init__(self) -> None:
        pass

    def close(self):
        pass

class KRBLdapShell:

    def __init__(self, ldap: LDAP, logger: Logger) -> None:
        self.ldap = ldap
        self.logger = logger
        self.fakeTcpClient = FakeTcpClient()

        self.domainDumper = DomainDumper(self.ldap)

        self.ldapshell = LdapShell(self.fakeTcpClient, self.domainDumper, self.ldap.Authentication())

    def run(self):
        cmd = ""
        
        while cmd != "exit":
            cmd = input("# ")
            try:
                func, line = cmd.split(" ", 1)
            except ValueError:
                func, line = cmd, ""

            if f"do_{func}" in dir(self.ldapshell):
                func = getattr(self.ldapshell, f"do_{func}")(line)
            else:
                print(f"Command '{cmd}' not found!")
