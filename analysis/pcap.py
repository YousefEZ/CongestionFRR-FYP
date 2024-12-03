from dataclasses import dataclass
from functools import cached_property
from typing import NamedTuple, Optional

import pyshark
from scapy.all import rdpcap, PacketList
from scapy.layers.inet import IP, TCP

SOURCE = "10.1.2.1"
DESTINATION = "10.1.6.2"


class Communication(NamedTuple):
    source: str
    destination: str


TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_ACK = 0x10


@dataclass(frozen=True)
class PcapFile:
    filename: str

    @cached_property
    def packets(self) -> PacketList:
        return rdpcap(self.filename)

    @property
    def first_addresses(self) -> Communication:
        return Communication(self.packets[0][IP].src, self.packets[0][IP].dst)

    def packets_from(self, source: str):
        return list(
            filter(lambda pkt: IP in pkt and pkt[IP].src == source, self.packets)
        )

    @cached_property
    def addresses(self) -> list[str]:
        return list(set([pkt[IP].src for pkt in self.packets]))

    def number_of_packets_from_source(self, source: str) -> int:
        return len(self.packets_from(source))

    def flow_completion_time(self, source: str, destination: str) -> Optional[float]:
        for packet in filter(lambda packet: TCP in packet, self.packets):
            if (
                packet.getlayer("IP").src == destination
                and packet.getlayer("IP").dst == source
                and packet[TCP].flags & TCP_FIN
                and packet[TCP].flags & TCP_ACK
            ):
                return float(packet.time)
        return None

    def number_of_packet_reordering_from_source(self, source: str) -> int:
        file_capture = pyshark.FileCapture(
            self.filename,
            display_filter=f"ip.src=={source} and tcp.analysis.out_of_order",
        )
        packets = list(file_capture)
        file_capture.close()
        return len(packets)
