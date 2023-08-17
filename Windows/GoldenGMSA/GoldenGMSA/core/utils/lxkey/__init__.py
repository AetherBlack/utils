
from ....constantes import KDSRootKeyAttributes

class L0Key:

    def __init__(self, rootKey: KDSRootKeyAttributes, l0keyID: int, derivedKey: bytes) -> None:
        self.l0KeyID = l0keyID
        self.kdsRootKeyData = derivedKey
