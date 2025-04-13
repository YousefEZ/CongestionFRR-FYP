from dataclasses import dataclass, field
from typing import override

import pyshark
import scapy
from scapy.layers.inet import TCP
import scapy.packet

from analysis.trace_analyzer.analyzer import PacketAnalyzer
from analysis.pcap import SMSS, PcapFile
from analysis.trace_analyzer.source.packet_capture import PacketCapture
from analysis.trace_analyzer.source.socket_state import SocketState


@dataclass(frozen=True)
class PacketOutOfOrderAnalyzer(PacketAnalyzer):
    file: PcapFile
    name: str = "Packet Out of Order"

    def filter_packets(
        self, source: str, destination: str
    ) -> list[scapy.packet.Packet]:
        file_capture = pyshark.FileCapture(
            self.file.filename,
            display_filter=f"ip.src=={source} and ip.dst=={destination} and tcp.analysis.out_of_order",
        )
        packets = [self.file.packets[int(packet.number) - 1] for packet in file_capture]
        file_capture.close()
        return packets


def hashable_packet(packet):
    return packet[TCP].seq, packet[TCP].ack, dict(packet[TCP].options)["Timestamp"]


@dataclass(frozen=True)
class OOOAnalyzer(PacketAnalyzer):
    sender: PcapFile
    receiver: PcapFile
    name: str = "Out of Order Packets"

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

        out_of_order_packets = []
        for sent_packet, received_packet in zip(
            delivered_sent_packets, received_packets
        ):
            if hashable_packet(sent_packet) != hashable_packet(received_packet):
                out_of_order_packets.append(sent_packet)

        return out_of_order_packets


@dataclass(frozen=True)
class PreciseOOOAnalyzer(PacketAnalyzer):
    sender: PcapFile
    receiver: PcapFile
    name: str = "Out of Order Packets"

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

        out_of_order_packets = []
        for sent_packet, received_packet in zip(
            delivered_sent_packets, received_packets
        ):
            if hashable_packet(sent_packet) != hashable_packet(received_packet):
                out_of_order_packets.append(sent_packet)

        return out_of_order_packets


@dataclass(frozen=True)
class SpuriousOOOAnalyzer(PacketAnalyzer):
    sender: PcapFile
    receiver: PcapFile
    name: str = "Spurious Retransmission due to OOO Packet"

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

        out_of_order_packets = []
        for sent_packet, received_packet in zip(
            delivered_sent_packets, received_packets
        ):
            if hashable_packet(sent_packet) != hashable_packet(received_packet):
                out_of_order_packets.append(sent_packet)

        ooo_seq = {packet[TCP].seq for packet in out_of_order_packets}
        spurious_retransmissions = []

        transmission_count = {packet[TCP].seq: 2 for packet in delivered_sent_packets}

        for sent_packet in delivered_sent_packets:
            if (
                sent_packet[TCP].seq in transmission_count
                and sent_packet[TCP].seq in ooo_seq
            ):
                if transmission_count[sent_packet[TCP].seq] > 1:
                    transmission_count[sent_packet[TCP].seq] -= 1
                else:
                    spurious_retransmissions.append(sent_packet)

        return spurious_retransmissions


@dataclass(frozen=True)
class SpuriousRetransmissionAnalyzer(PacketAnalyzer):
    sender: PcapFile
    receiver: PcapFile
    name: str = "Spurious Retransmissions"

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

        spurious_retransmissions = []
        already_transmitted = set()

        for sent_packet in delivered_sent_packets:
            if sent_packet[TCP].seq in already_transmitted:
                spurious_retransmissions.append(sent_packet)
            already_transmitted.add(sent_packet[TCP].seq)

        return spurious_retransmissions


@dataclass
class SpuriousOOORTOCapture(PacketCapture):
    spurious_ooo_packets: list[tuple[int, int, float]] = field(default_factory=list)
    spurious_ooo_burst_count: int = field(default_factory=int)
    longest_spurious_ooo_burst_count: int = field(default_factory=int)

    @override
    def on_retransmission_timeout(
        self, packet: scapy.packet.Packet, state: SocketState
    ):
        self.longest_spurious_ooo_burst_count = max(
            self.spurious_ooo_burst_count, self.longest_spurious_ooo_burst_count
        )
        self.spurious_ooo_burst_count = 0

    @override
    def on_retransmission(self, packet: scapy.packet.Packet, state: SocketState):
        if hashable_packet(packet) in self.spurious_ooo_packets:
            self.spurious_ooo_burst_count += 1


class RTOTimeCapture(PacketCapture):
    rto_times: list[float] = field(default_factory=list)

    @override
    def on_retransmission_timeout(
        self, packet: scapy.packet.Packet, state: SocketState
    ):
        self.rto_times.append(state.time - state.last_send_timestamp)


@dataclass
class DroppedRetransmittedPacketCapture(PacketCapture):
    retransmitted_packets: list[scapy.packet.Packet] = field(default_factory=list)
    dropped_packets: list[scapy.packet.Packet] = field(default_factory=list)
    next_retransmission: bool = field(default=False)

    @override
    def on_retransmission_timeout(
        self, packet: scapy.packet.Packet, state: SocketState
    ) -> None:
        print("Timeout at ", packet[TCP].seq)
        for rtx_packet in self.retransmitted_packets:
            if rtx_packet[TCP].seq == packet[TCP].seq:
                self.dropped_packets.append(rtx_packet)
                return

    @override
    def on_retransmission(
        self, packet: scapy.packet.Packet, state: SocketState
    ) -> None:
        self.retransmitted_packets.append(packet)


@dataclass
class TrueBytesInFlightAnalyzer(PacketCapture):
    lost_packets: list[tuple[float, int]] = field(default_factory=list)
    bytes_in_flight: list[tuple[float, int]] = field(default_factory=list)
    current_bytes_in_flight: int = field(default=1)

    @override
    def on_new_send(self, packet: scapy.packet.Packet, state: SocketState) -> None:
        self.current_bytes_in_flight += hashable_packet(packet) not in self.lost_packets
        self.bytes_in_flight.append((state.time, self.current_bytes_in_flight))

    @override
    def on_retransmission_timeout(
        self, packet: scapy.packet.Packet, state: SocketState
    ) -> None:
        hashed_packet = hashable_packet(packet)
        self.current_bytes_in_flight += hashed_packet not in self.lost_packets
        self.bytes_in_flight.append((state.time, self.current_bytes_in_flight))

    @override
    def on_retransmission(
        self, packet: scapy.packet.Packet, state: SocketState
    ) -> None:
        hashed_packet = hashable_packet(packet)
        self.current_bytes_in_flight += hashed_packet not in self.lost_packets
        self.bytes_in_flight.append((state.time, self.current_bytes_in_flight))

    @override
    def on_ack(self, packet: scapy.packet.Packet, state: SocketState) -> None:
        self.current_bytes_in_flight -= 1
        self.bytes_in_flight.append((state.time, self.current_bytes_in_flight))

    @override
    def on_dup_ack(self, packet: scapy.packet.Packet, state: SocketState) -> None:
        self.current_bytes_in_flight -= 1
        self.bytes_in_flight.append((state.time, self.current_bytes_in_flight))


def tcp_bytes_in_flight(debug_filename: str, sender: int) -> list[tuple[float, int]]:
    bytes_in_flight: list[tuple[float, int]] = []
    string = f"[node {sender + 6}] Returning calculated bytesInFlight: "
    with open(debug_filename, "r") as debug_file:
        for line in debug_file:
            if string in line:
                bytes_in_flight.append(
                    (
                        float(line.split("s")[0]),
                        int(line.split(": ")[1]) // SMSS,
                    )
                )
    return bytes_in_flight


def congestion_windows(filename: str) -> list[tuple[float, int]]:
    congestion_windows: list[tuple[float, int]] = []
    with open(filename, "r") as debug_file:
        for line in debug_file:
            time, cwnd, *_ = line.split(" ")
            if cwnd.strip().isnumeric():
                congestion_windows.append((float(time), int(cwnd)))
    return congestion_windows
