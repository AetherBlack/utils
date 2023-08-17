#!/usr/bin/env python3

from impacket.examples.utils import parse_credentials
from impacket.examples import logger

import argparse
import logging
import sys

from .core.utils.ldap import Authentication
from .core import *

def main():
    parser = argparse.ArgumentParser(add_help=True, description="Abuse Group Managed Service Accounts (gMSA) in Active Directory")
    parser.add_argument("target", action="store", help="domain[/username[:password]]")
    parser.add_argument("-ts", action="store_true", help="Adds timestamp to every logging output")
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    group = parser.add_argument_group("authentication")
    group.add_argument("-hashes", action="store", metavar="LMHASH:NTHASH", help="NTLM hashes, format is LMHASH:NTHASH")
    group.add_argument("-no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    group.add_argument("-k", action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file "
                                                        "(KRB5CCNAME) based on target parameters. If valid credentials "
                                                        "cannot be found, it will use the ones specified in the command "
                                                        "line")
    group.add_argument("-aesKey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication "
                                                                            "(128 or 256 bits)")

    group = parser.add_argument_group("connection")
    group.add_argument("-dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If "
                                                                                "ommited it use the domain part (FQDN) "
                                                                                "specified in the target parameter")
    group.add_argument("-domain-name", action="store", required=True, metavar="domain name", help="Domain name of the domain controller to use")

    sub_parser = parser.add_subparsers(dest="action")
    gmsainfo_parser = sub_parser.add_parser("gmsainfo", help="Query gMSA information")
    gmsainfo_parser.add_argument("-sid", action="store", help="The SID of the gMSA account to query")

    kdsinfo_parser = sub_parser.add_parser("kdsinfo", help="Query KDS Root Keys information")
    kdsinfo_parser.add_argument("-guid", action="store", help="The GUID of the KDS Root Key object to query")

    compute_parser = sub_parser.add_parser("compute", help="Compute gMSA passwords")
    compute_parser.add_argument("-sid", action="store", required=True, help="SID of the gMSA")
    compute_parser.add_argument("-kdskey", action="store", help="Base64 encoded KDS Root Key")
    compute_parser.add_argument("-pwdid", action="store", help="Base64 of msds-ManagedPasswordID attribut value")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.target)

    if not len(domain):
        logging.critical('Domain should be specified!')
        sys.exit(1)
    
    askPassword = all([
        password == "",
        username != "",
        options.hashes is None,
        options.no_pass is False,
        options.aesKey is None
    ])

    if askPassword:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey:
        options.k = True

    authentication = Authentication(options.domain_name, domain, options.dc_ip or options.domain_name, username, password, options.k)

    try:
        if options.action == "gmsainfo":
            func = gMSA(authentication, options.sid)
        elif options.action == "kdsinfo":
            func = KDSRootKey(authentication, options.guid)
        elif options.action == "compute":
            func = ComputegMSAPasswords(authentication, options.sid, options.kdskey, options.pwdid)
        else:
            raise NotImplementedError

        func.run()

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))

if __name__ == "__main__":
    main()
