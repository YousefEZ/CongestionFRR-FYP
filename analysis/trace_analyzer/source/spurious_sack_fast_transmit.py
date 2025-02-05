from dataclasses import dataclass
from typing import override

import scapy
import scapy.packet

from analysis.trace_analyzer.analyzer import PacketAnalyzer
from analysis.trace_analyzer.source import replayer
from analysis.trace_analyzer.source.socket_state import SocketState
from analysis.trace_analyzer.source.packet_capture import PacketCapture
from analysis.pcap import PcapFile
from analysis.trace_analyzer.source._utils import (
    calculate_sack_packets,
)


@dataclass
class SingleDupAckRetransmitPacketCapture(PacketCapture):
    """This Packet Capture detects spurious retransmitted packets, and on the first DUP ACK the simulator
    retransmits the packet because the flow is at that current point of time in OPEN mode,
    and therefore as noted in RFC 6675, section 5, if we received a DUP ACK in this state,
    then TCP would check (step 2) if DupAcks < DupThresh but IsLost(HighACK + 1).
    The sequence number is classed as lost as we have received sacked bytes above that sequence number,
    and the DUP ACK threshold is 3 x SMSS.
    """

    @override
    def on_retransmission(
        self, packet: scapy.packet.Packet, state: SocketState
    ) -> None:
        if state.dup_ack != replayer.DUPLICATE_ACK_THRESHOLD and (
            calculate_sack_packets(state.sacked_bytes)
            >= replayer.DUPLICATE_ACK_THRESHOLD
        ):
            self.packets.append(packet)


@dataclass(frozen=True)
class SingleDupAckRetransmitSackAnalyzer(PacketAnalyzer):
    file: PcapFile
    name: str = "Single Dup Ack Fast Retransmit"

    def filter_packets(
        self, source: str, destination: str
    ) -> list[scapy.packet.Packet]:
        capture = SingleDupAckRetransmitPacketCapture()
        replayer.TcpSourceReplayer(
            file=self.file,
            source=source,
            destination=destination,
            event_handlers=capture,
        ).run()
        return capture.packets
