
from ....constantes import KDSRootKeyAttributes
from ...kdsinfo import KDSRootKey
from ..kdscli import KDSCli
from ..lxkey import L0Key

class GetKey:

    @staticmethod
    def getSidKeyLocal(securityDescriptor: bytes, sDSize: int, rootKey: KDSRootKeyAttributes, l0KeyId: int, l1KeyId: int, l2KeyId: int, accessCheckFailed: int, domainName: str, forestName: str) -> None:
        
        l0Key = GetKey.ComputeL0Key(rootKey, l0KeyId)
    
    def ComputeL0Key(rootKey: KDSRootKeyAttributes, l0KeyId: int) -> L0Key:
        rootKeyGuid = rootKey.cn

        errCode, kdfContent, kdfContentSize, kdfContextFlag = KDSCli.generateKDFContext(
            rootKeyGuid, l0KeyId,
            0xffffffff, 0xffffffff,
            0,
            0, 0, 0
        )

        if (errCode != 0):
            raise NotImplementedError
        
        generateDerivedKey = bytearray(KDSRootKey.KdsRootKeyDataSizeDefault)
        labelSize = 0
        label = bytes()

        KDSCli.generateDerivedKey(
            
        )