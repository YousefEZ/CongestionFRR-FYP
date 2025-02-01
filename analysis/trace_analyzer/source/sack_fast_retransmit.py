from dataclasses import dataclass
from typing import override

import scapy
import scapy.packet
from scapy.layers.inet import TCP

from analysis.pcap import PcapFile
from analysis.trace_analyzer.analyzer import PacketAnalyzer
from analysis.trace_analyzer.source import replayer
from analysis.trace_analyzer.source.socket_state import SocketState
from analysis.trace_analyzer.source.packet_capture import PacketCapture

from analysis.trace_analyzer.source.replayer import DUPLICATE_ACK_THRESHOLD


@dataclass
class FastRetransmitSackPacketCapture(PacketCapture):
    """This Packet Capture detects retransmitted packets as being lost, noted in RFC 6675, section 5,
    if we received a DUP ACK in this state,then TCP would check (step 2)
    if DupAcks < DupThresh but IsLost(HighACK + 1). The sequence number is classed as lost as
    we have received sacked bytes above that sequence number, and the DUP ACK threshold is 3 x SMSS.
    """

    @override
    def on_retransmission(
        self, packet: scapy.packet.Packet, state: SocketState
    ) -> None:
        if state.sack_dupacks[packet[TCP].seq] == DUPLICATE_ACK_THRESHOLD:
            self.packets.append(packet)


@dataclass(frozen=True)
class FastRetransmitSackAnalyzer(PacketAnalyzer):
    file: PcapFile
    name: str = "SACK Fast Retransmit"

    def filter_packets(
        self, source: str, destination: str
    ) -> list[scapy.packet.Packet]:
        capture = FastRetransmitSackPacketCapture()
        replayer.TcpSourceReplayer(
            file=self.file,
            source=source,
            destination=destination,
            event_handlers=capture,
        ).run()
        return capture.packets
