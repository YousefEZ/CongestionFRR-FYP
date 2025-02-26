from dataclasses import dataclass, field

import scapy
from scapy.all import Raw
import scapy.packet
from scapy.layers.inet import IP, TCP

from analysis.pcap import SMSS, TCP_ACK, PcapFile
from analysis.trace_analyzer.source.socket_state import SocketState
from analysis.trace_analyzer.source.packet_capture import PacketCapture
from analysis.trace_analyzer.source._utils import (
    calculate_dropped_packets,
    get_sacked_byte_ranges,
    get_sacked_segments,
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

    def _update_scoreboard(self, segment: int) -> None:
        if segment not in self.state.scoreboard:
            self.event_handlers.on_scoreboard_add(segment, self.state)
            self.state.scoreboard.add(segment)

    def _cumulative_ack(self, packet: scapy.packet.Packet) -> None:
        for segment in range(self.state.last_acked_seq, packet[TCP].ack + SMSS, SMSS):
            self._update_scoreboard(segment)

    def _handle_sacks(self, packet: scapy.packet.Packet) -> None:
        sacks = get_sacked_byte_ranges(packet)
        if sacks is not None:
            for segment in get_sacked_segments(sacks):
                self._update_scoreboard(segment)
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
        if (
            packet[TCP].ack > self.state.recovery_point
            and self.state.recovery_point != 0
        ):
            self._exit_recovery()
        self._clear_dup_acks()
        self.state.last_acked_seq = packet[TCP].ack
        self._cumulative_ack(packet)

    def _handle_ack(self, packet: scapy.packet.Packet):
        if self._is_dup_ack(packet):
            self._handle_dup_ack(packet)
        else:
            self._handle_new_ack(packet)

        self.state.last_ack_timestamp = float(packet.time)

    def _handle_new_transmission(self, packet: scapy.packet.Packet):
        self.event_handlers.on_new_send(packet, self.state)
        self.state.high_tx_mark = packet[TCP].seq

    def _handle_retransmission(self, packet: scapy.packet.Packet):
        if not self.state.in_recovery:
            self._enter_recovery(packet, self.state)
        self.event_handlers.on_retransmission(packet, self.state)

    def _enter_recovery(self, packet: scapy.packet.Packet, state: SocketState):
        self.state.high_rtx = packet[TCP].seq
        self.state.recovery_point = state.high_tx_mark
        self.state.in_recovery = True
        self.event_handlers.on_enter_recovery(state)

    def _exit_recovery(self):
        self.event_handlers.on_exit_recovery(self.state)
        self.state.high_rtx = 0
        self.state.recovery_point = 0
        self.state.in_recovery = False

    def _handle_retransmission_timeout(self, packet: scapy.packet.Packet):
        self.event_handlers.on_retransmission_timeout(packet, self.state)
        if self.state.in_recovery:
            # could be not enough DUP ACKs causing rto to expire without recovery
            self._exit_recovery()

    def _handle_send(self, packet: scapy.packet.Packet) -> None:
        if Raw not in packet:
            return

        if packet[TCP].seq > self.state.high_tx_mark:
            self._handle_new_transmission(packet)
        else:
            if (
                float(packet.time)
                - float(self.state.last_sent_timestamps[packet[TCP].seq])
                >= 0.9
            ):
                self._handle_retransmission_timeout(packet)
            else:
                self._handle_retransmission(packet)

        self.state.last_sent_timestamps[packet[TCP].seq] = float(packet.time)
        self.state.last_send_timestamp = float(packet.time)

    def run(self) -> None:
        for packet in self.file.packets:
            self.state.time = float(packet.time)
            if packet[IP].dst == self.source:
                self._handle_ack(packet)
                continue
            self._handle_send(packet)
