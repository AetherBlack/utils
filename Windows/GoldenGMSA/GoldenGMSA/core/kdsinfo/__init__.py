
import base64

from ...constantes import KDSRootKeyAttributes
from ..utils.ldap import LDAP, Authentication
from ..utils.logger import Logger

class KDSRootKey:

    KdsRootKeyDataSizeDefault = 64

    def __init__(self, authentication: Authentication, guid: str) -> None:
        self.authentication = authentication

        if guid:
            self.filter = f"(&(objectClass=msKds-ProvRootKey)(cn={guid}))"
        else:
            self.filter = "(objectClass=msKds-ProvRootKey)"

        self.ldap = LDAP(self.authentication)

    def getKDSRootKeyEntries(self) -> list:
        return self.ldap.query(self.ldap.getConfigurationNamingContext(), LDAP.SUB, self.filter, attributes=KDSRootKeyAttributes.__all__)

    def getKDSRootKeyAttributes(self, kdsRootKey: bytes) -> KDSRootKeyAttributes:
        return KDSRootKeyAttributes(kdsRootKey)

    def run(self) -> None:
        entries = self.getKDSRootKeyEntries()

        if len(entries):
            for entry in entries:
                kdsRootKey = self.getKDSRootKeyAttributes(entry)

                rootKey = base64.b64encode(kdsRootKey.rootKeyData.raw_values[0]).decode()
                
                Logger.information(f"GUID: {kdsRootKey.cn}")
                Logger.information(f"blob: {rootKey}")
        else:
            Logger.warning("No entries found")
