
import struct

class KDSCli:

    def generateKDFContext(guid: bytes, contextInit: int, contextInit2: int, contextInit3: int, flag: int, outContext: int = 0,
                           outContextSize: int = 0, flag2: int = 0) -> int:
        # MOV contextInit, 0x10
        contextInit = 0x10

        # MOV contextInit2, qword ptr [RSP + flag2]
        contextInit2 = flag2

        # MOVUPS XMMO0, xmmword ptr [RSI]
        # MOVDQU xmmword ptr [sidKeyProv],XMM0
        sidKeyProv = guid

        # MOV dword ptr [sidKeyProv + 0x10], EDI
        sidKeyProv += struct.pack("<L", contextInit)

        contextInit = 0x10
        # JC LAB_180008e0e
        if (flag != 0):
            contextInit = 0x10
            if (flag2 != 0x0):
                contextInit = 0x14
        
        sidKeyProv += struct.pack("<L", contextInit2)

        if ((1 < flag) and (flag2 != 0x0)):
            contextInit += 0x4
        
        sidKeyProv += struct.pack("<L", contextInit3)

        outContext = sidKeyProv
        outContextSize = 0x1c
        errCode = 0

        if (flag2 != 0x0):
            flag2 = contextInit
            errCode = 0
        
        return errCode, outContext, outContextSize, flag2

    def generateDerivedKey(kdfAlgorithmId: str, kdfParam: bytes, kdfParamSize: int, pbSecret: bytes, cbSecret: int, context: bytes,
                           contextSize: int, notSure: int, label: bytes, labelSize: int, notsureFlag: int, pbDerivedKey: bytes, cbDerivedKey: int, AlwaysZero: int):
        pass
