from dataclasses import dataclass
from functools import cached_property
from typing import NamedTuple

import pyshark
import scapy.packet
from scapy.all import rdpcap, PacketList
from scapy.layers.inet import IP, TCP, UDP

SOURCE = "10.1.2.1"
DESTINATION = "10.1.7.2"

SMSS = 1446


class Communication(NamedTuple):
    source: str
    destination: str


TCP_FIN = 0b00_0000_0001
TCP_SYN = 0b00_0000_0010
TCP_ACK = 0b00_0001_0000


@dataclass(frozen=True)
class PcapFile:
    filename: str

    @cached_property
    def packets(self) -> PacketList:
        return rdpcap(self.filename)

    @cached_property
    def tcp_packets(self) -> list[scapy.packet.Packet]:
        return [pkt for pkt in self.packets if TCP in pkt]

    @cached_property
    def udp_packets(self) -> list[scapy.packet.Packet]:
        return [pkt for pkt in self.packets if UDP in pkt]

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

    def flow_completion_time(self, source: str, destination: str) -> float:
        for packet in self.tcp_packets:
            if (
                packet.getlayer("IP").src == destination
                and packet.getlayer("IP").dst == source
                and packet[TCP].flags & TCP_FIN
                and packet[TCP].flags & TCP_ACK
            ):
                return float(packet.time)
        assert False, "Flow completion time not found"

    def number_of_packet_reordering_from_source(self, source: str) -> int:
        file_capture = pyshark.FileCapture(
            self.filename,
            display_filter=f"ip.src=={source} and tcp.analysis.out_of_order",
        )
        packets = list(file_capture)
        print(self.filename, len(packets))

        file_capture.close()
        return len(packets)
