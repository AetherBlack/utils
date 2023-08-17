
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.krb5.crypto import string_to_key
from impacket.krb5 import constants

import hashlib
import base64

from ...constantes import gMSAAttributes, MSDS_MANAGEDPASSWORD_BLOB, MSDS_MANAGEDPASSWORDID_BLOB
from ..utils.ldap import LDAP, Authentication
from ..utils.logger import Logger

class gMSA:

    def __init__(self, authentication: Authentication, sid: str) -> None:
        self.authentication = authentication

        if sid:
            self.filter = f"(&(objectClass=msDS-GroupManagedServiceAccount)(objectSid={sid}))"
        else:
            self.filter = "(objectClass=msDS-GroupManagedServiceAccount)"

        self.ldap = LDAP(self.authentication)
    
    def computeHash(self, data: bytes, domain: str, samAccountName: str) -> None:
        blob = MSDS_MANAGEDPASSWORD_BLOB()
        blob.fromString(data)
        currentPassword: bytes = blob['CurrentPassword'][:-2]

        # NT
        nt = hashlib.new("md4", currentPassword).hexdigest()
        Logger.to_stdout(f"{samAccountName}:::{nt}")

        # AES
        password = currentPassword.decode("utf-16-le", "replace").encode()
        salt = f"{domain.upper()}host{samAccountName[:-1].lower()}.{domain.lower()}"

        aes_256_hash: bytes = string_to_key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, password, salt).contents
        Logger.to_stdout(f"{samAccountName}:aes256-cts-hmac-sha1-96:{aes_256_hash.hex()}")
        
        aes_128_hash: bytes = string_to_key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, password, salt).contents
        Logger.to_stdout(f"{samAccountName}:aes128-cts-hmac-sha1-96:{aes_128_hash.hex()}")

    def getgMSAEntries(self) -> list:
        if self.ldap.ldaps:
            gMSAAttributes.__all__.append(gMSAAttributes.managedPassword)

        return self.ldap.query(self.ldap.defaultNamingContext, LDAP.SUB, self.filter, attributes=gMSAAttributes.__all__)

    def getMsDsManagedPasswordIDBlob(self, managedPasswordID: bytes) -> MSDS_MANAGEDPASSWORDID_BLOB:
        return MSDS_MANAGEDPASSWORDID_BLOB().fromString(managedPasswordID)

    def run(self) -> None:
        entries = self.getgMSAEntries()

        if len(entries):
            for k, entry in enumerate(entries):
                if k: Logger.to_stdout("")

                gmsa = gMSAAttributes(entry)

                Logger.information(f"sAMAccountName: {gmsa.samAccountName}")
                Logger.information(f"ObjectSID: {gmsa.objectSid}")

                blob = self.getMsDsManagedPasswordIDBlob(gmsa.managedPasswordID.value)
                Logger.information(f"RootKeyGuid: {blob['RootKeyIdentifier']}")

                if len(gmsa.groupMSAMembership):
                    Logger.information("Groups/Users who can read password:")

                    for member in SR_SECURITY_DESCRIPTOR(data=gmsa.groupMSAMembership.raw_values[0])["Dacl"]["Data"]:
                        member_sid = member["Ace"]["Sid"].formatCanonical()
                        entries = self.ldap.query(self.ldap.defaultNamingContext, LDAP.SUB, f"(objectSid={member_sid})", attributes=["sAMAccountName"])

                        if len(entries):
                            Logger.to_stdout(f"\t{entries[0]['sAMAccountName'].value}", end="")
                        Logger.to_stdout(f" ({member_sid})")
                
                if gmsa.managedPassword:
                    managedPassword = base64.b64encode(gmsa.managedPassword.raw_values[0]).decode()
                    Logger.information(f"ManagedPassword: {managedPassword}")
                    self.computeHash(gmsa.managedPassword.raw_values[0], self.authentication.domain_name, gmsa.samAccountName.value)
        else:
            Logger.warning("No entries found")
