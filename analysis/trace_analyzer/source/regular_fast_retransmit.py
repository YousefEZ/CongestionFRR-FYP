from dataclasses import dataclass

import pyshark
import scapy
import scapy.packet

from analysis.trace_analyzer.analyzer import PacketAnalyzer
from analysis.pcap import PcapFile


@dataclass(frozen=True)
class PacketOutOfOrderAnalyzer(PacketAnalyzer):
    file: PcapFile

    def filter_packets(
        self, source: str, destination: str
    ) -> list[scapy.packet.Packet]:
        file_capture = pyshark.FileCapture(
            self.file.filename,
            display_filter=f"ip.src=={source} and ip.dst=={destination} and tcp.analysis.out_of_order",
        )
        packets = [self.file.packets[int(packet.number)] for packet in file_capture]
        file_capture.close()
        return packets


@dataclass(frozen=True)
class SpuriousRetransmissionAnalyzer(PacketAnalyzer):
    file: PcapFile

    def filter_packets(
        self, source: str, destination: str
    ) -> list[scapy.packet.Packet]:
        file_capture = pyshark.FileCapture(
            self.file.filename,
            display_filter=f"ip.src=={source} and ip.dst=={destination} and tcp.analysis.spurious_retransmission",
        )
        packets = [self.file.packets[int(packet.number)] for packet in file_capture]
        file_capture.close()
        return packets


@dataclass(frozen=True)
class FastRetransmissionAnalyzer(PacketAnalyzer):
    file: PcapFile

    def filter_packets(
        self, source: str, destination: str
    ) -> list[scapy.packet.Packet]:
        file_capture = pyshark.FileCapture(
            self.file.filename,
            display_filter=f"ip.src=={source} and ip.dst=={destination} and tcp.analysis.retransmission",
        )
        packets = [self.file.packets[int(packet.number) - 1] for packet in file_capture]
        print(packets)
        file_capture.close()
        return packets
