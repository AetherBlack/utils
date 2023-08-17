
import base64

from ...constantes import gMSAAttributes, MSDS_MANAGEDPASSWORDID_BLOB, KDSRootKeyAttributes
from ..utils.ldap import Authentication
from ...core.kdsinfo import KDSRootKey
from ..utils.kdsutils import KDSUtils
from ...core.gmsainfo import gMSA
from ..utils.getkey import GetKey
from ..utils.logger import Logger

class ComputegMSAPasswords:

    def __init__(self, authentication: Authentication, sid: str, kdskey: str, pwdid: str) -> None:
        self.authentication = authentication
        self.filter = list()
        self.kdskey = kdskey
        self.pwdid = pwdid
        self.sid = sid

        self.gmsa = gMSA(self.authentication, self.sid)
        self.kdsRootKey = KDSRootKey(self.authentication, None)

    def getManagedPasswordIDBySid(self) -> MSDS_MANAGEDPASSWORDID_BLOB:
        """
        Get msDs-ManagedPasswordId from LDAP.
        """
        pwdIdBlob = gMSAAttributes(self.gmsa.getgMSAEntries()[0]).managedPasswordID.value
        return self.gmsa.getMsDsManagedPasswordIDBlob(pwdIdBlob)

    def getPasswordID(self, pwdid: bytes) -> MSDS_MANAGEDPASSWORDID_BLOB:
        """
        Get msDs-ManagedPasswordId.
        """
        if pwdid:
            return self.gmsa.getMsDsManagedPasswordIDBlob(base64.b64decode(pwdid))
        else:
            return self.getManagedPasswordIDBySid()

    def getRootKeyByGuid(self) -> KDSRootKeyAttributes:
        """
        Get RootKeyIdentifier from LDAP.
        """
        self.kdsRootKey = KDSRootKey(self.authentication, self.pwdid["RootKeyIdentifier"])
        return self.kdsRootKey.getKDSRootKeyAttributes(self.kdsRootKey.getKDSRootKeyEntries()[0])

    def getKDSKey(self, kdskey: bytes) -> KDSRootKeyAttributes:
        """
        Get RootKeyIdentifier.
        """
        if kdskey:
            return self.kdsRootKey.getKDSRootKeyAttributes(base64.b64decode(kdskey))
        else:
            self.kdsRootKey = KDSRootKey(self.authentication, self.pwdid["RootKeyIdentifier"])
            return self.getRootKeyByGuid()

    def getPassword(self, sid: str, kdskey: KDSRootKeyAttributes, pwdid: MSDS_MANAGEDPASSWORDID_BLOB, domain_name: str) -> None:
        return gMSAPassword(sid, kdskey, pwdid, domain_name).getPassword()

    def run(self) -> None:
        # Pwdid
        self.pwdid = self.getPasswordID(self.pwdid)

        # Kdskey
        self.kdskey = self.getKDSKey(self.kdskey)

        # Compute password with pwdid, kdskey and sid
        password = self.getPassword(self.sid, self.kdskey, self.pwdid, self.authentication.domain_name)

class gMSAPassword:

    DefaultGMSASecurityDescriptor = bytearray([
        0x1, 0x0, 0x4, 0x80, 0x30, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x0, 0x1C, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x14, 0x0, 0x9F, 0x1, 0x12, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x9,
        0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x12, 0x0, 0x0, 0x0
    ])

    def __init__(self, sid: str, kdskey: KDSRootKeyAttributes, pwdid: MSDS_MANAGEDPASSWORDID_BLOB, domain_name: str) -> None:
        self.domain_name = domain_name
        self.kdskey = kdskey
        self.pwdid = pwdid
        self.sid = sid

    def getSidKeyLocal(self, securityDescriptor: bytes, sDSize: int, rootKey: int, l0KeyId: int, l1KeyId: int, l2KeyId: int, accessCheckFailed: int, domainName: str, forestName: str, gke, gkeSize) -> None:
        pass

    def getPassword(self) -> str:

        l0KeyID, l1KeyID, l2KeyID = KDSUtils.getCurrentIntervalID(KDSUtils.KeyCycleDuration, 0)

        gke = GetKey.getSidKeyLocal(
            self.DefaultGMSASecurityDescriptor,
            len(self.DefaultGMSASecurityDescriptor),
            self.kdskey,
            l0KeyID, l1KeyID, l2KeyID,
            0,
            self.domain_name, self.domain_name
        )

        gkeSize = len(gke)

        return