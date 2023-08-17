
from impacket.krb5.crypto import Key, _AESEnctype
from impacket.krb5.asn1 import EncASRepPart, EncTGSRepPart

from typing import Any

class Types:

    EncASRepPart = EncASRepPart
    EncTGSRepPart = EncTGSRepPart
    Encype = _AESEnctype
    Key = Key
    Any = Any
