
import ldap3

from ..logger import Logger

class Authentication:

    def __init__(self, domain_name: str, domain: str, host: str, username: str, password: str, kerberosAuthentication: bool = False, auto_bind: bool = True) -> None:
        self.domain_name = domain_name
        self.auto_bind = auto_bind
        self.username = username
        self.password = password
        self.domain = domain
        self.host = host

        if kerberosAuthentication:
            self.authentication_method = ldap3.SASL
        else:
            self.authentication_method = ldap3.NTLM

class LDAP:

    SUB = ldap3.SUBTREE

    def __init__(self, authentication: Authentication) -> None:
        self.authentication = authentication
        self.ldaps = False

        if self.authentication.host:
            self.server = ldap3.Server(self.authentication.host, get_info=ldap3.ALL)
        else:
            self.server = ldap3.Server(self.authentication.domain, get_info=ldap3.ALL)

        if self.authentication.authentication_method == ldap3.NTLM:
            self.ldapConnection = ldap3.Connection(
                self.server,
                user='{}\\{}'.format(self.authentication.domain, self.authentication.username),
                password=self.authentication.password,
                authentication=self.authentication.authentication_method,
                auto_bind=self.authentication.auto_bind
            )
        elif self.authentication.authentication_method == ldap3.SASL:
            self.ldapConnection = ldap3.Connection(
                self.server,
                authentication=self.authentication.authentication_method,
                sasl_mechanism=ldap3.KERBEROS,
                auto_bind=self.authentication.auto_bind
            )

        try:
            self.ldapConnection.start_tls()
            self.ldaps = True
        except:
            Logger.warning("Unable to start TLS.")
        
        self.defaultNamingContext = self.getDefaultNamingContext()
    
    def getDefaultNamingContext(self) -> str:
        return "DC=" + ",DC=".join(self.authentication.domain_name.split("."))

    def getConfigurationNamingContext(self) -> None:
        return "CN=Configuration," + self.defaultNamingContext

    def query(self, base: str, scope: str, filter: str, attributes: str) -> list:
        """
        `base` => 
        `scope` => sub, base, one, children
        `filter` => which data retrieve
        `attributes` => ``
        """
        status = self.ldapConnection.search(base, filter, search_scope=scope, attributes=attributes)

        if status:
            return self.ldapConnection.entries
        else:
            Logger.error("LDAP query failed")
            Logger.error(status)
