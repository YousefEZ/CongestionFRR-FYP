from dataclasses import dataclass
from typing import override

import scapy
from scapy.layers.inet import TCP
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


def hashable_packet(packet):
    return packet[TCP].seq, packet[TCP].ack, dict(packet[TCP].options)["Timestamp"]


@dataclass(frozen=True)
class SingleDupAckRetransmitSackAnalyzer(PacketAnalyzer):
    sender: PcapFile
    receiver: PcapFile
    name: str = "Single Dup Ack Fast Retransmit"

    def filter_packets(
        self, source: str, destination: str
    ) -> list[scapy.packet.Packet]:
        received_packets = self.receiver.packets_from(source)
        sent_packets = self.sender.packets_from(source)

        hashed_received_packets = [
            hashable_packet(packet) for packet in received_packets
        ]

        delivered_sent_packets = [
            packet
            for packet in sent_packets
            if hashable_packet(packet) in hashed_received_packets
        ]

        spurious_retransmissions = set()
        already_transmitted = set()

        for sent_packet in delivered_sent_packets:
            if sent_packet[TCP].seq in already_transmitted:
                spurious_retransmissions.add(hashable_packet(sent_packet))
            already_transmitted.add(sent_packet[TCP].seq)

        capture = SingleDupAckRetransmitPacketCapture()
        replayer.TcpSourceReplayer(
            file=self.sender,
            source=source,
            destination=destination,
            event_handlers=capture,
        ).run()

        return [
            packet
            for packet in capture.packets
            if hashable_packet(packet) in spurious_retransmissions
        ]
