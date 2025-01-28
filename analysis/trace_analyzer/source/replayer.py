from dataclasses import dataclass, field

import scapy
import scapy.packet
from scapy.layers.inet import IP, TCP

from analysis.pcap import TCP_ACK, PcapFile
from analysis.trace_analyzer.source.socket_state import SocketState
from analysis.trace_analyzer.source.packet_capture import PacketCapture
from analysis.trace_analyzer.source._utils import (
    calculate_dropped_packets,
    get_sacked_byte_ranges,
)

DUPLICATE_ACK_THRESHOLD = 3


@dataclass(frozen=True)
class TcpSourceReplayer:
    file: PcapFile
    source: str
    destination: str
    event_handlers: PacketCapture
    state: SocketState = field(default_factory=SocketState)

    def _is_dup_ack(self, packet: scapy.packet.Packet) -> bool:
        return (
            packet[TCP].flags & TCP_ACK and packet[TCP].ack == self.state.last_acked_seq
        )

    def _increment_dup_ack(self):
        if self.state.dup_ack != DUPLICATE_ACK_THRESHOLD:
            self.state.dup_ack += 1

    def _clear_dup_acks(self):
        self.event_handlers.on_clear_dup_acks(self.state)
        self.state.dup_ack = 0
        self.state.sack_dupacks.clear()

    def _handle_sacks(self, packet: scapy.packet.Packet) -> None:
        sacks = get_sacked_byte_ranges(packet)
        if sacks is not None:
            for dropped_packet in calculate_dropped_packets(sacks):
                if self.state.sack_dupacks[dropped_packet] != DUPLICATE_ACK_THRESHOLD:
                    self.state.sack_dupacks[dropped_packet] += 1

        if sacks != self.state.sacked_bytes:
            self.event_handlers.on_new_sack(sacks, self.state)
            self.state.sacked_bytes = sacks

    def _handle_dup_ack(self, packet: scapy.packet.Packet):
        self.event_handlers.on_dup_ack(packet, self.state)
        self._handle_sacks(packet)
        self._increment_dup_ack()

    def _handle_new_ack(self, packet: scapy.packet.Packet):
        self.event_handlers.on_ack(packet, self.state)
        self._clear_dup_acks()
        self.state.last_acked_seq = packet[TCP].ack

    def _handle_ack(self, packet: scapy.packet.Packet):
        if self._is_dup_ack(packet):
            self._handle_dup_ack(packet)
        else:
            self._handle_new_ack(packet)

    def _handle_new_transmission(self, packet: scapy.packet.Packet):
        self.event_handlers.on_new_send(packet, self.state)
        self.state.high_tx_mark = packet[TCP].seq

    def _handle_retransmission(self, packet: scapy.packet.Packet):
        self.event_handlers.on_retransmission(packet, self.state)

    def _handle_send(self, packet: scapy.packet.Packet) -> None:
        if packet[TCP].seq > self.state.high_tx_mark:
            self._handle_new_transmission(packet)
        else:
            self._handle_retransmission(packet)

    def run(self) -> None:
        for packet in self.file.packets:
            if packet[IP].dst == self.source:
                self._handle_ack(packet)
                continue
            self._handle_send(packet)
