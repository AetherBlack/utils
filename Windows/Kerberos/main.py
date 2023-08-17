
from TGT import AuthenticationService
from TGS import TicketGrantingService

from logger import Logger

import constants

if __name__ == "__main__":

    USERNAME = "mig"
    PASSWORD = "Pwd2023"
    DOMAIN   = "openclassroom.intra"
    SPN      = "LDAP/SRV-AD-BDX-01.openclassroom.intra"

    authenticationService = AuthenticationService(USERNAME, PASSWORD, DOMAIN, preAuth=False)

    tgt          : bytes
    encASRepPart : constants.Types.EncASRepPart
    cipher       : constants.Types.Encype
    key          : constants.Types.Key
    sessionKey   : constants.Types.Key

    Logger.warning("Authentication Service")
    Logger.information("Lancement de la requête AS-REQ")
    Logger.information(f"Demande de pré-authentification pour l'utilisateur {USERNAME} auprès du KDC {DOMAIN}")

    tgt, encASRepPart, cipher, key, sessionKey = authenticationService.run()

    Logger.information("Réponse AS-REP du serveur:")

    decodedTGT = authenticationService.decodeTGT(tgt)
    Logger.ok(decodedTGT)

    Logger.information("Le contenu du champ enc-part de la partie ticket ne peut être lu qu'avec le secret du compte krbtgt:")
    Logger.ok(decodedTGT["ticket"])

    Logger.information("Contenu du champ enc-part de la réponse AS-REP:")
    Logger.ok(encASRepPart)

    Logger.information("La clé de session partagé pour cette session est:")
    Logger.ok(encASRepPart["key"]["keyvalue"].asOctets().hex())

    #print(tgt)
    #print(encASRepPart)
    #print(cipher)
    #print(key)
    #print(sessionKey)

    Logger.to_stdout("")

    tgs           : constants.Types.Any
    encTGSRepPart : constants.Types.EncTGSRepPart
    cipher        : constants.Types.Key
    sessionKey    : constants.Types.Key
    newSessionKey : constants.Types.Key

    ticketGrantingService = TicketGrantingService(tgt, cipher, sessionKey, DOMAIN, SPN, DOMAIN)

    Logger.warning("Ticket Granting Service")
    Logger.information("Lancement de la requête TGS-REQ")
    Logger.information(f"Demande de Service Ticket pour l'utilisateur {USERNAME} au service {SPN} auprès du KDC {DOMAIN}")

    tgs, encTGSRepPart, cipher, sessionKey, newSessionKey = ticketGrantingService.run()

    Logger.information("Réponse TGS-REP du serveur:")

    decodedTGS = ticketGrantingService.decodeTGS(tgs)
    Logger.ok(decodedTGS)

    Logger.information("Le contenu du champ enc-part de la partie ticket ne peut être lu qu'avec le secret du compte krbtgt:")
    Logger.ok(decodedTGS["ticket"])

    Logger.information("Contenu du champ enc-part de la réponse TGS-REP:")
    Logger.ok(encTGSRepPart)

    Logger.information("La clé de session partagé pour cette session est:")
    Logger.ok(encTGSRepPart["key"]["keyvalue"].asOctets().hex())


    #print(tgs)
    #print(encTGSRepPart)
    #print(cipher)
    #print(sessionKey)
    #print(newSessionKey)


    #print(decodedTGS)
