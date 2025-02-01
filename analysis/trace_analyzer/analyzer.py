from typing import Protocol

import scapy.packet


class PacketAnalyzer(Protocol):
    name: str

    def filter_packets(
        self, source: str, destination: str
    ) -> list[scapy.packet.Packet]: ...
