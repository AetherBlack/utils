
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5.crypto import Key, _AESEnctype
from impacket.krb5.crypto import _enctype_table
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.krb5.asn1 import AP_REQ, TGS_REP, TGS_REQ, AS_REP, EncTGSRepPart, EncAPRepPart, Authenticator
from impacket.krb5.asn1 import seq_set, seq_set_iter
from impacket.krb5 import constants

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from typing import Any

import datetime
import random

from TGT import KDCOptions, AuthenticationService

class APOptions:

    reserved        = 0
    use_session_key = 0
    mutual_required = 0

    def flags(self) -> list:
        array = list()

        for flag in dir(self):
            if not flag.startswith("_") and not flag == "flags":
                cflag = getattr(self, flag)

                if cflag and isinstance(cflag, int):
                    apFlag = getattr(constants.APOptions, flag)

                    array.append(apFlag.value)

        return array

class TicketGrantingService:

    def __init__(self, tgt: bytes, cipher: _AESEnctype, sessionKey: Key, domain: str, spn: str, kdcHost: str = None, kdcOptions: KDCOptions = None, apOptions: APOptions = None) -> None:
        self.__tgt        = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        self.__cipher     = cipher
        self.__sessionKey = sessionKey
        self.__domain     = domain
        self.__kdcHost    = kdcHost if kdcHost else self.__domain
        self.__serverName = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        self.__kdcOptions = kdcOptions
        self.__apOptions  = apOptions

        # Extract the ticket from the TGT
        self._ticket = Ticket()
        self._ticket.from_asn1(self.__tgt["ticket"])

    def decodeTGS(self, tgs: bytes) -> TGS_REP:
        return decoder.decode(tgs, asn1Spec=TGS_REP())[0]

    def _buildTGSReqApReqMsgType(self, apReq: AP_REQ) -> None:
        """
        Add pvno and msg-type
        """
        apReq["pvno"] = 5
        apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    def _buildTGSReqApReqOptions(self, apReq: AP_REQ) -> None:
        """
        Set options
        """
        if not self.__apOptions:
            self.__apOptions = APOptions()
        
        apReq["ap-options"] =  constants.encodeFlags(self.__apOptions.flags())
        seq_set(apReq, "ticket", self._ticket.to_asn1)

    def _buildTGSReqAuthenticator(self, apReq: AP_REQ) -> None:
        """
        Set authenticator.
        """
        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"] = self.__tgt["crealm"].asOctets()

        clientName = Principal()
        clientName.from_asn1(self.__tgt, "crealm", "cname")

        seq_set(authenticator, "cname", clientName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator["cusec"] =  now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = self.__cipher.encrypt(self.__sessionKey, 7, encodedAuthenticator, None)

        apReq["authenticator"] = noValue
        apReq["authenticator"]["etype"] = self.__cipher.enctype
        apReq["authenticator"]["cipher"] = encryptedEncodedAuthenticator

    def _buildTGSReqApReq(self) -> Any:
        """
        Kerberos tgs-req contains :
        - msg-type (ap-req)
        - ticket
        - authenticator

        :returns apReq
        """
        apReq = AP_REQ()

        # KRB AP_REQ
        self._buildTGSReqApReqMsgType(apReq)

        # Options
        self._buildTGSReqApReqOptions(apReq)

        # Authenticator
        self._buildTGSReqAuthenticator(apReq)

        return apReq

    def _buildTGSReqMsgType(self, tgsReq: TGS_REQ) -> None:
        """
        Add pvno, msg-type.
        """
        tgsReq["pvno"] =  5
        tgsReq["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

    def _buildTGSReqPreAuthData(self, tgsReq: TGS_REQ, apReq: AP_REQ) -> None:
        """
        Add PreAuthentication data.
        """
        encodedApReq = encoder.encode(apReq)

        tgsReq["padata"] = noValue
        tgsReq["padata"][0] = noValue
        tgsReq["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq["padata"][0]["padata-value"] = encodedApReq

    def _buildTGSReqBody(self, tgsReq: TGS_REQ) -> None:
        """
        Add body.
        """
        reqBody = seq_set(tgsReq, "req-body")

        if not self.__kdcOptions:
            self.__kdcOptions = KDCOptions()
            self.__kdcOptions.forwardable  = 1
            self.__kdcOptions.renewable    = 1
            self.__kdcOptions.renewable_ok = 1
            self.__kdcOptions.canonicalize = 1

        reqBody['kdc-options'] = constants.encodeFlags(self.__kdcOptions.flags())
        seq_set(reqBody, 'sname', self.__serverName.components_to_asn1)
        reqBody['realm'] = self.__domain

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody["till"] = KerberosTime.to_asn1(now)
        reqBody["nonce"] = random.SystemRandom().getrandbits(31)
        seq_set_iter(reqBody, "etype",
                        (
                            int(constants.EncryptionTypes.rc4_hmac.value),
                            int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                            int(constants.EncryptionTypes.des_cbc_md5.value),
                            int(self.__cipher.enctype)
                        )
                    )


    def buildTGSReq(self) -> Any:
        """
        :returns TGS-REQ
        """
        tgsReq = TGS_REQ()

        # KRB AP_REQ
        apReq = self._buildTGSReqApReq()

        # KRB TGS_REQ
        self._buildTGSReqMsgType(tgsReq)

        # padata
        self._buildTGSReqPreAuthData(tgsReq, apReq)

        # Req body
        self._buildTGSReqBody(tgsReq)

        return tgsReq

    def sendPacket(self, req: Any) -> Any:
        """
        Send packet.
        :returns message
        """
        # Encore message
        message = encoder.encode(req)

        return sendReceive(message, self.__domain, self.__kdcHost)

    def parseTGSRep(self, r: Any) -> Any:
        """
        """
        # Get the session key
        tgs = decoder.decode(r, asn1Spec = TGS_REP())[0]

        cipherText = tgs["enc-part"]["cipher"]

        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plainText = self.__cipher.decrypt(self.__sessionKey, 8, cipherText)

        encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]

        newSessionKey = Key(encTGSRepPart["key"]["keytype"], encTGSRepPart["key"]["keyvalue"].asOctets())

        # Creating new cipher based on received keytype
        cipher = _enctype_table[encTGSRepPart["key"]["keytype"]]

        # Check we've got what we asked for
        res = decoder.decode(r, asn1Spec = TGS_REP())[0]
        spn = Principal()
        spn.from_asn1(res["ticket"], "realm", "sname")

        return r, encTGSRepPart, cipher, self.__sessionKey, newSessionKey

    def run(self):
        """
        Build TGS, sendPacket and parse TGS-REP

        :returns message, cipher, sessionKey and newSessionKey
        """
        tgsReq = self.buildTGSReq()
        message = self.sendPacket(tgsReq)
        return self.parseTGSRep(message)
        

if __name__ == "__main__":

    USERNAME = "mig"
    PASSWORD = "Pwd2023"
    DOMAIN   = "openclassroom.intra"

    authenticationService = AuthenticationService(USERNAME, PASSWORD, DOMAIN)

    tgt          : bytes
    encASRepPart : EncAPRepPart
    cipher       : _AESEnctype
    key          : Key
    sessionKey   : Key

    tgt, encASRepPart, cipher, key, sessionKey = authenticationService.run()

    SPN = "LDAP/SRV-AD-BDX-01.openclassroom.intra"

    tgs           : Any
    encTGSRepPart : EncTGSRepPart
    cipher        : Key
    sessionKey    : Key
    newSessionKey : Key

    ticketGrantingService = TicketGrantingService(tgt, cipher, sessionKey, DOMAIN, SPN, DOMAIN)

    tgs, encTGSRepPart, cipher, sessionKey, newSessionKey = ticketGrantingService.run()

    print(tgs)
    print(encTGSRepPart)
    print(cipher)
    print(sessionKey)
    print(newSessionKey)
