from dataclasses import dataclass, field
import logging

import scapy
import scapy.packet

from analysis.trace_analyzer.source.socket_state import SocketState, SackedByteRange


# TODO: ideally socket state should be traced using descriptors, which would have callbacks injected
@dataclass
class PacketCapture:
    packets: list[scapy.packet.Packet] = field(default_factory=list)

    def on_retransmission(
        self, packet: scapy.packet.Packet, state: SocketState
    ) -> None:
        logging.debug(f"Retransmission detected: {packet.summary()} in state={state}")

    def on_dup_ack(self, packet: scapy.packet.Packet, state: SocketState) -> None:
        logging.debug(f"Dup ACK detected: {packet.summary()} in state={state}")

    def on_ack(self, packet: scapy.packet.Packet, state: SocketState) -> None:
        logging.debug(f"ACK detected: {packet.summary()} in state={state}")

    def on_new_sack(
        self, sack_byte_ranges: list[SackedByteRange], state: SocketState
    ) -> None:
        logging.debug(f"New SACK ranges: {sack_byte_ranges} in state={state}")

    def on_clear_dup_acks(self, state: SocketState) -> None:
        logging.debug(f"Clearing dup acks in state={state}")

    def on_new_send(self, packet: scapy.packet.Packet, state: SocketState) -> None:
        logging.debug(f"New transmission detected: {packet.summary()} in state={state}")

    def on_retransmission_timeout(
        self, packet: scapy.packet.Packet, state: SocketState
    ) -> None:
        logging.debug(f"Retransmission timeout in state={state}")

    def on_exit_recovery(self, state: SocketState) -> None:
        logging.debug(f"Exiting recovery in state={state}")

    def on_enter_recovery(self, state: SocketState) -> None:
        logging.debug(f"Entering recovery in state={state}")

    def on_scoreboard_add(self, segment: int, state: SocketState) -> None:
        logging.debug(f"Adding segment to scoreboard: {segment} in state={state}")
