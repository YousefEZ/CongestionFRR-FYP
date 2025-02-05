from dataclasses import dataclass

from scapy.layers.inet import TCP
import scapy.packet


from analysis.pcap import PcapFile
from analysis.trace_analyzer.analyzer import PacketAnalyzer


@dataclass(frozen=True)
class DroppedPacketsAnalyzer(PacketAnalyzer):
    sender: PcapFile
    receiver: PcapFile
    name: str = "Dropped Packets"

    def filter_packets(
        self, source: str, destination: str
    ) -> list[scapy.packet.Packet]:
        # all sent packets

        sent_packets = {
            (packet[TCP].seq, dict(packet[TCP].options)["Timestamp"]): packet
            for packet in self.sender.packets_from(source)
        }
        received_packets = {
            (packet[TCP].seq, dict(packet[TCP].options)["Timestamp"])
            for packet in self.receiver.packets_from(source)
        }

        # remove packets that are in sent_packets but not in received_packets
        dropped_packets = set(sent_packets.keys()) - received_packets
        return [sent_packets[packet] for packet in dropped_packets]
