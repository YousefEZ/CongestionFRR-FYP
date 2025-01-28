from typing import Protocol

import scapy.packet

from analysis.pcap import PcapFile


class PacketAnalyzer(Protocol):
    def __init__(self, file: PcapFile): ...

    def filter_packets(
        self, source: str, destination: str
    ) -> list[scapy.packet.Packet]: ...
