
from impacket.krb5.kerberosv5 import AS_REQ, AS_REP, KERB_PA_PAC_REQUEST, KerberosError, SessionKeyDecryptionError
from impacket.krb5.kerberosv5 import seq_set_iter, sendReceive
from impacket.krb5.crypto import Key, InvalidChecksum, _AESEnctype
from impacket.krb5.crypto import _enctype_table
from impacket.krb5.types import Principal, KerberosTime
from impacket.krb5.asn1 import PA_ENC_TS_ENC, EncryptedData, EncASRepPart
from impacket.krb5.asn1 import seq_set
from impacket.krb5 import constants

from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue

from typing import Any

import datetime
import random

class KDCOptions:

    reserved                = 0
    forwardable             = 0
    forwarded               = 0
    proxiable               = 0
    proxy                   = 0
    allow_postdate          = 0
    postdated               = 0
    unused7                 = 0

    renewable               = 0
    unused9                 = 0
    unused10                = 0
    opt_hardware_auth       = 0
    unused12                = 0
    unused13                = 0
    cname_in_addl_tkt       = 0
    canonicalize            = 0

    disable_transited_check = 0
    renewable_ok            = 0
    enc_tkt_in_skey         = 0
    renew                   = 0
    validate                = 0

    def flags(self) -> list:
        array = list()

        for flag in dir(self):
            if not flag.startswith("_") and not flag == "flags":
                cflag = getattr(self, flag)

                if cflag and isinstance(cflag, int):
                    kdcFlag = getattr(constants.KDCOptions, flag)

                    array.append(kdcFlag.value)

        return array


class AuthenticationService:

    def __init__(self, username: str, password: str, domain: str, kdcHost: str = None, preAuth: bool = True, nthash: str = "", aesKey: str = "", kdcOptions: KDCOptions = None, debug: bool = False) -> None:
        self.__username      = username
        self.__password      = password
        self.__domain        = domain.upper()
        self.__kdcHost       = kdcHost if kdcHost else self.__domain
        self.__preAuth       = preAuth
        self.__nthash        = nthash.encode()
        self.__aesKey        = aesKey.encode()
        self.__aes256        = True if not len(self.__nthash) and len(aesKey) == 32 else False
        self.__aes128        = True if not len(self.__nthash) and len(aesKey) != 32 else False
        self.__rc4           = not any([self.__aes128, self.__aes256])
        self.__kdcOptions    = kdcOptions
        self.__debug         = debug
        self._cipher         = None
        self._key            = None
        self._currentCiphers = None

        self.clientName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        self.serverName = Principal(f"krbtgt/{self.__domain}", type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    def decodeTGT(self, tgt: bytes) -> AS_REP:
        return decoder.decode(tgt, asn1Spec=AS_REP())[0]

    def _buildASReqMsgType(self, asReq: AS_REQ) -> None:
        """
        Add pvno and msg-type
        """
        asReq["pvno"] = 5
        asReq["msg-type"] =  int(constants.ApplicationTagNumbers.AS_REQ.value)

    def _buildASReqPreAuthData(self, asReq: AS_REQ) -> None:
        """
        Add PAC to asReq
        (PA = PreAuthentication, PAC = Privilege Attribute Certificate)
        """
        # pA-ENC-TIMESTAMP
        if self.__preAuth:

            # Let's build the timestamp
            timeStamp = PA_ENC_TS_ENC()

            now = datetime.datetime.utcnow()
            timeStamp['patimestamp'] = KerberosTime.to_asn1(now)
            timeStamp['pausec'] = now.microsecond

            # Encrypt the shyte
            encodedTimeStamp = encoder.encode(timeStamp)

            # Key Usage 1
            # AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the
            # client key (Section 5.2.7.2)
            encriptedTimeStamp = self._cipher.encrypt(self._key, 1, encodedTimeStamp, None)

            encryptedData = EncryptedData()
            encryptedData['etype'] = self._cipher.enctype
            encryptedData['cipher'] = encriptedTimeStamp
            encodedEncryptedData = encoder.encode(encryptedData)

        # pA-PAC-REQUEST
        paPacData = KERB_PA_PAC_REQUEST()
        paPacData["include-pac"] = True
        encodedPaPacdata = encoder.encode(paPacData)

        asReq["padata"] = noValue
        asReq["padata"][0] = noValue
        if self.__preAuth:
            asReq["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value)
            asReq['padata'][0]['padata-value'] = encodedEncryptedData

            asReq["padata"][1] = noValue
            asReq["padata"][1]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
            asReq["padata"][1]["padata-value"] = encodedPaPacdata
        else:
            asReq["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
            asReq["padata"][0]["padata-value"] = encodedPaPacdata

    def _getASReqBodyCipher(self, asReq: Any) -> list:
        # Need test
        return asReq["req-body"]["etype"]

    def _setASReqBodyCipher(self, asReq: Any) -> None:
        """
        Set etype
        """
        seq_set_iter(asReq["req-body"], 'etype', self._currentCiphers)

    def _prepareCipher(self) -> None:
        """
        Prepare cipher and key.
        """
        if self.__rc4:
            supportedCiphers = (
                int(constants.EncryptionTypes.rc4_hmac.value),
            )
        elif self.__aes128:
            supportedCiphers = (
                int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
            )
        else:
            supportedCiphers = (
                int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
            )

        self._currentCiphers = supportedCiphers

        encryptionTypesData = dict()
        enctype = self._currentCiphers[0]
        # Can be _RC4 too, the class share the same functions
        self._cipher: _AESEnctype = _enctype_table[enctype]

        # In case it's a machine
        if self.__username.endswith("$"):
            salt = (self.__domain + self.__username.lower()[:-1] + "." + self.__domain.lower()).encode()
        else:
            salt = (self.__domain + self.__username).encode()

        if self._currentCiphers[0] in [constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, constants.EncryptionTypes.aes256_cts_hmac_sha1_96]:
            encryptionTypesData[self._currentCiphers[0]] = salt
        else:
            # handle RC4 fallback, we don't need any salt
            encryptionTypesData[self._currentCiphers[0]] = b""

        if len(self.__nthash):
            self._key = Key(self._cipher.enctype, self.__nthash)
        elif len(self.__aesKey):
            self._key = Key(self._cipher.enctype, self.__aesKey)
        else:
            self._key = self._cipher.string_to_key(self.__password, encryptionTypesData[enctype], None)

    def _setASReqBodyKDCOptions(self, reqBody: Any) -> Any:
        if not self.__kdcOptions:
            self.__kdcOptions = KDCOptions()
            self.__kdcOptions.forwardable = 1
            self.__kdcOptions.proxiable   = 1
            self.__kdcOptions.renewable   = 1

        reqBody["kdc-options"] = constants.encodeFlags(self.__kdcOptions.flags())

        return reqBody


    def _buildASReqBody(self, asReq: AS_REQ) -> None:
        """
        Add Body
        """

        reqBody = seq_set(asReq, "req-body")
        reqBody = self._setASReqBodyKDCOptions(reqBody)

        seq_set(reqBody, 'cname', self.clientName.components_to_asn1)
        seq_set(reqBody, 'sname', self.serverName.components_to_asn1)

        reqBody['realm'] = self.__domain

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        reqBody['till']  = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        # etype
        self._setASReqBodyCipher(asReq)

    def buildASReq(self) -> Any:
        """
        Kerberos as-req contains :
        - msg-type (as-req),
        - padata (Preauthentication request),
        - req-body (Data)
        
        :returns asReq
        """

        asReq = AS_REQ()

        # KRB AS_REQ
        self._buildASReqMsgType(asReq)

        # Prepare cipher for the next fields
        self._prepareCipher()

        # padata
        self._buildASReqPreAuthData(asReq)

        # Req body
        self._buildASReqBody(asReq)

        # That all for the packet construction
        return asReq

    def sendPacket(self, req: Any) -> Any:
        """
        Send packet.
        In case etype is not supported, resend with the other etype (rc4 <=> aes).
        :returns message
        """
        # Encode message
        message = encoder.encode(req)

        try:
            return sendReceive(message, self.__domain, self.__kdcHost)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                supportedCiphers = self._getASReqBodyCipher(req)

                if supportedCiphers[0] in (constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value):
                    self._currentCiphers = constants.EncryptionTypes.rc4_hmac.value
                elif supportedCiphers[0] == constants.EncryptionTypes.rc4_hmac.value:
                    self._currentCiphers = constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value
                else: raise

                self._setASReqBodyCipher(req)
                # Check to avoid infinite loop ?
                return self.sendPacket(req)

    def parseASRep(self, r: Any) -> Any:
        """
        Parse message r.
        :returns tgt and session key.
        """
        try:
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        except:
            print(f"preAuth is {self.__preAuth} but need to be {not self.__preAuth}")
            raise

        # So, we have the TGT, now extract the new session key and finish
        cipherText = asRep["enc-part"]["cipher"]

        if not self.__preAuth and self.__debug:
            print(
                "$krb5asrep$%d$%s@%s:%s$%s" % (
                        asRep["enc-part"]["etype"],
                        self.clientName,
                        self.__domain,
                        asRep["enc-part"]["cipher"].asOctets()[:16].hex(),
                        asRep["enc-part"]["cipher"].asOctets()[16:].hex()
                    )
            )

        # Key Usage 3
        # AS-REP encrypted part (includes TGS session key or
        # application session key), encrypted with the client key
        # (Section 5.4.2)
        try:
            plainText = self._cipher.decrypt(self._key, 3, cipherText)
        except InvalidChecksum as e:
            # probably bad password if preauth is disabled
            if not self.__preAuth:
                error_msg = "failed to decrypt session key: %s" % str(e)
                raise SessionKeyDecryptionError(error_msg, asRep, self._cipher, self._key, cipherText)
            raise

        encASRepPart = decoder.decode(plainText, asn1Spec = EncASRepPart())[0]

        # Get the session key and the ticket
        self._cipher = _enctype_table[encASRepPart["key"]["keytype"]]
        sessionKey = Key(self._cipher.enctype,encASRepPart["key"]["keyvalue"].asOctets())

        return r, encASRepPart, self._cipher, self._key, sessionKey

    def run(self) -> Any:
        asReq = self.buildASReq()
        message = self.sendPacket(asReq)
        return self.parseASRep(message)

if __name__ == "__main__":

    USERNAME = "mig"
    PASSWORD = "Pwd2023"
    DOMAIN   = "openclassroom.intra"

    authenticationService = AuthenticationService(USERNAME, PASSWORD, DOMAIN, preAuth=True)

    tgt          : bytes
    encASRepPart : EncASRepPart
    cipher       : _AESEnctype
    key          : Key
    sessionKey   : Key

    tgt, encASRepPart, cipher, key, sessionKey = authenticationService.run()

    print(authenticationService.decodeTGT(tgt))
    print(encASRepPart)
    print(cipher)
    print(key.contents)
    print(sessionKey.contents)
