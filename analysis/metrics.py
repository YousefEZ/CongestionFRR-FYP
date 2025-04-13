from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING


from analysis.graph import Plot
from analysis.trace_analyzer.dst.reordered_packets import (
    DroppedRetransmittedPacketCapture,
    SpuriousOOORTOCapture,
    SpuriousRetransmissionAnalyzer,
    hashable_packet,
)
from analysis.trace_analyzer.source.replayer import TcpSourceReplayer

if TYPE_CHECKING:
    from analysis.scenario import VariableRun, WaitTimeAfterRTO, RTOWaitingForUnsent


def extract_numerical_value_from_string(string: str) -> float:
    index = 0
    for index, character in enumerate(string):
        if not character.isdigit() and character != ".":
            break
    numerical_value = float(string[:index])
    return numerical_value


def _calculate_packet_loss(
    packets_at_source: int, packets_at_destination: int
) -> float:
    return (1 - (packets_at_destination / packets_at_source)) * 100


class Metric(ABC):
    name: str

    @classmethod
    def fetch_metrics(cls, variable_run: VariableRun) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=cls.calculate(variable_run, variable),
                )
                for variable in variable_run.variables
            ),
            key=lambda plot: plot.variable,
        )

    @staticmethod
    @abstractmethod
    def calculate(variable_run: VariableRun, variable: str) -> int | float:
        raise NotImplementedError("Abstract Method, implement in subclass")


class PacketLoss(Metric):
    name = "Packet Loss"

    @staticmethod
    def calculate(variable_run: VariableRun, variable: str) -> float:
        addresses = variable_run.ip_addresses(variable)
        source_pcap = variable_run.pcap(variable, "TrafficSender0", 1)
        destination_pcap = variable_run.pcap(variable, "Receiver", 1)
        source_packets = source_pcap.number_of_packets_from_source(addresses.source)
        destination_packets = destination_pcap.number_of_packets_from_source(
            addresses.source
        )
        return _calculate_packet_loss(source_packets, destination_packets)


class RTOWaitTimeForUnsent(Metric):
    name = "RTO Wait Time for Unsent"

    @staticmethod
    def calculate(variable_run: VariableRun, variable: str) -> float:
        capture = RTOWaitingForUnsent()
        TcpSourceReplayer(
            variable_run.pcap(variable, "TrafficSender0", 1),
            *variable_run.ip_addresses(variable),
            capture,
        ).run()
        return capture.wait_time


class RTOWaitTime(Metric):
    name = "RTO Wait Time"

    @staticmethod
    def calculate(variable_run: VariableRun, variable: str) -> float:
        capture = WaitTimeAfterRTO()
        TcpSourceReplayer(
            variable_run.pcap(variable, "TrafficSender0", 1),
            *variable_run.ip_addresses(variable),
            capture,
        ).run()
        return capture.wait_time


class PacketsLost(Metric):
    name = "Packets Lost"

    @staticmethod
    def calculate(variable_run: VariableRun, variable: str) -> int:
        addresses = variable_run.ip_addresses(variable)
        destination_pcap = variable_run.pcap(variable, "Receiver", 1)
        destination_packets = destination_pcap.number_of_packets_from_source(
            addresses.source
        )
        return variable_run.packets_sent_by_source(variable) - destination_packets


class UDPPacketsLost(Metric):
    name = "UDP Packets Lost"

    @staticmethod
    def calculate(variable_run: VariableRun, variable: str) -> int:
        sent = len(variable_run.pcap(variable, "CongestionSender", 1).packets)
        received = len(variable_run.pcap(variable, "Receiver", 1).udp_packets)
        return sent - received


class UDPPacketLoss(Metric):
    name = "UDP Packet Loss"

    @staticmethod
    def calculate(variable_run: VariableRun, variable: str) -> float:
        sent = len(variable_run.pcap(variable, "CongestionSender", 1).packets)
        if sent == 0:
            return 0.0
        received = len(variable_run.pcap(variable, "Receiver", 1).udp_packets)
        return _calculate_packet_loss(sent, received)


class PacketsRerouted(Metric):
    name = "Packets Rerouted"

    @staticmethod
    def calculate(variable_run: VariableRun, variable: str) -> int:
        addresses = variable_run.ip_addresses(variable)
        rerouted_pcap = variable_run.pcap(variable, "Router03", 1)
        return rerouted_pcap.number_of_packets_from_source(addresses.source)


class UDPPacketsRerouted(Metric):
    name = "UDP Packets Rerouted"

    @staticmethod
    def calculate(variable_run: VariableRun, variable: str) -> int:
        rerouted_pcap = variable_run.pcap(variable, "Router03", 1)
        return len(rerouted_pcap.udp_packets)


class UDPPacketsReroutedPercentage(Metric):
    name = "UDP Packets Rerouted Percentage"

    @staticmethod
    def calculate(variable_run: VariableRun, variable: str) -> float:
        udp_packets_sent = len(
            variable_run.pcap(variable, "CongestionSender", 1).packets
        )
        if udp_packets_sent == 0:
            return 0.0
        return (
            len(variable_run.pcap(variable, "Router03", 1).udp_packets)
            / udp_packets_sent
        ) * 100


class DroppedRetransmittedPackets(Metric):
    name = "Dropped Retransmitted Packets"

    @staticmethod
    def calculate(variable_run: VariableRun, variable: str) -> int:
        capture = DroppedRetransmittedPacketCapture()
        TcpSourceReplayer(
            variable_run.pcap(variable, "TrafficSender0", 1),
            *variable_run.ip_addresses(variable),
            capture,
        ).run()
        return len(capture.dropped_packets)


class PacketsReroutedPercentage(Metric):
    name = "Packets Rerouted Percentage"

    @staticmethod
    def calculate(variable_run: VariableRun, variable: str) -> float:
        return (
            variable_run.packets_rerouted_at(variable)
            / variable_run.packets_sent_by_source(variable)
        ) * 100


class LongestSpuriousRetransmissionsBeforeRTO(Metric):
    name = "Longest Spurious Retransmissions Before RTO"

    @staticmethod
    def calculate(variable_run: VariableRun, variable: str) -> int:
        spur_ooo_packets = SpuriousRetransmissionAnalyzer(
            variable_run.pcap(variable, "TrafficSender0", 1),
            variable_run.pcap(variable, "Receiver", 1),
        ).filter_packets(*variable_run.ip_addresses(variable))

        burst_capture = SpuriousOOORTOCapture(
            spurious_ooo_packets=[hashable_packet(p) for p in spur_ooo_packets]
        )
        TcpSourceReplayer(
            variable_run.pcap(variable, "TrafficSender0", 1),
            *variable_run.ip_addresses(variable),
            burst_capture,
        ).run()

        return burst_capture.longest_spurious_ooo_burst_count


class SpuriousRetransmissionsFromReordering(Metric):
    name = "Spurious Retransmissions From Reordering"

    @staticmethod
    def calculate(variable_run: VariableRun, variable: str) -> int:
        spur_ooo_packets = SpuriousRetransmissionAnalyzer(
            variable_run.pcap(variable, "TrafficSender0", 1),
            variable_run.pcap(variable, "Receiver", 1),
        ).filter_packets(*variable_run.ip_addresses(variable))

        burst_capture = SpuriousOOORTOCapture(
            spurious_ooo_packets=[hashable_packet(p) for p in spur_ooo_packets]
        )
        TcpSourceReplayer(
            variable_run.pcap(variable, "TrafficSender0", 1),
            *variable_run.ip_addresses(variable),
            burst_capture,
        ).run()

        return burst_capture.longest_spurious_ooo_burst_count
