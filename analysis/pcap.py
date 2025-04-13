from dataclasses import dataclass
from functools import cached_property
from typing import NamedTuple
import time

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
        pyshark_cap = pyshark.FileCapture(
            self.filename,
            display_filter=f"tcp.flags.fin==1 and tcp.flags.ack==1 and ip.src=={destination}",
        )
        last_packet = None
        for packet in pyshark_cap:
            last_packet = packet
        if last_packet:
            timestamp = float(last_packet.sniff_timestamp)
            pyshark_cap.close()
            return timestamp
        assert False, "Flow completion time not found"

    def flow_completion_times(
        self, destination: str, tries: int = 0
    ) -> dict[str, float]:
        try:
            pyshark_cap = pyshark.FileCapture(
                self.filename,
                display_filter=f"tcp.flags.fin==1 and tcp.flags.ack==1 and ip.src=={destination}",
            )

            times = {
                packet.ip.dst: float(packet.sniff_timestamp) for packet in pyshark_cap
            }
            pyshark_cap.close()
        except Exception as e:
            print(f"Failed to load pcap file, attempt={tries}")
            time.sleep(tries)
            if tries >= 3:
                raise e
            return self.flow_completion_times(destination, tries + 1)
        return times

    def number_of_packet_reordering_from_source(self, source: str) -> int:
        file_capture = pyshark.FileCapture(
            self.filename,
            display_filter=f"ip.src=={source} and tcp.analysis.out_of_order",
        )
        packets = list(file_capture)

        file_capture.close()
        return len(packets)
