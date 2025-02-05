from dataclasses import field
import operator
from typing import Callable

from scapy.all import dataclass
import scapy.packet

from analysis.pcap import DESTINATION, SOURCE, PcapFile
import plotly.graph_objects as go
from analysis.trace_analyzer.analyzer import PacketAnalyzer
from analysis.trace_analyzer.source.dropped_packets import DroppedPacketsAnalyzer
from analysis.trace_analyzer.source.regular_fast_retransmit import (
    FastRetransmissionAnalyzer,
)
from analysis.trace_analyzer.source.sack_fast_retransmit import (
    FastRetransmitSackAnalyzer,
)
from analysis.trace_analyzer.source.spurious_sack_fast_transmit import (
    SingleDupAckRetransmitSackAnalyzer,
)

LINE_COLOURS = [
    "red",
    "cyan",
    "lime",
    "orange",
]

PREMADE_COLORS = ["blue", "green", "purple", "brown", "pink", "grey"]

SYMBOLS = [
    "square",
    "diamond",
    "cross",
    "x",
    "triangle-up",
    "star",
    "hexagram",
]


@dataclass(frozen=True)
class Packets:
    origin: str
    packets: list[scapy.packet.Packet]
    extract: Callable[[scapy.packet.Packet], int]
    conditions: dict[str, list[scapy.packet.Packet]] = field(default_factory=dict)


def build_conditions(
    *analyzers: PacketAnalyzer, source: str, destination: str
) -> dict[str, list[scapy.packet.Packet]]:
    conditions = {}
    filtered_packets = set()
    for analyzer in analyzers:
        packets = analyzer.filter_packets(source, destination)
        conditions[analyzer.name] = [
            packet
            for packet in packets
            if (packet.seq, packet.ack, float(packet.time)) not in filtered_packets
        ]
        filtered_packets.update(
            (packet.seq, packet.ack, float(packet.time)) for packet in packets
        )
    return conditions


def assign_from(assignments: dict[str, str], condition: str, values: list[str]) -> str:
    for value in values:
        if value not in assignments.values():
            assignments[condition] = value
            return value
    assert False, "Too many conditions to plot, add more colours"


def plot_sequence_plot(
    packets: Packets,
    fig: go.Figure,
    assigned_colours: dict[str, str],
    assigned_symbols: dict[str, str],
) -> None:
    origin_colour = assign_from(assigned_colours, packets.origin, values=LINE_COLOURS)
    for condition in packets.conditions:
        assign_from(assigned_colours, condition, values=PREMADE_COLORS)
        assign_from(assigned_symbols, condition, values=SYMBOLS)

    fig.add_trace(
        go.Scatter(
            x=[float(pkt.time) for pkt in packets.packets],
            y=[packets.extract(pkt) for pkt in packets.packets],
            mode="lines+markers",
            line_shape="hv",  # Step plot style
            name=packets.origin,
            line=dict(color=origin_colour),
            marker=dict(color=origin_colour),
            hovertemplate="Time: %{x}<br>Seq: %{y}<extra></extra>",
        )
    )
    for condition in packets.conditions:
        fig.add_trace(
            go.Scatter(
                x=[float(pkt.time) for pkt in packets.conditions[condition]],
                y=[packets.extract(pkt) for pkt in packets.conditions[condition]],
                mode="markers",
                marker=dict(
                    color=assigned_colours[condition],
                    symbol=assigned_symbols[condition],
                    size=12,
                ),
                name=f"{packets.origin}: {condition}",
            )
        )


def plot_sequence(*packets_list: Packets) -> None:
    """
    Plots the sequence numbers for sender and receiver on a single graph with
    custom markers for packets matching specific conditions.

    Args:
        sender_data (list[tuple[float, int, Any]]): Sequence data for the sender.
        receiver_data (list[tuple[float, int, Any]]): Sequence data for the receiver.
        sender_conditions (dict[str, Callable[[Any], bool]]): Conditions for sender packets.
        receiver_conditions (dict[str, Callable[[Any], bool]]): Conditions for receiver packets.
    """

    fig = go.Figure()
    assigned_colours: dict[str, str] = dict()
    assigned_symbols: dict[str, str] = dict()
    for packets in packets_list:
        plot_sequence_plot(packets, fig, assigned_colours, assigned_symbols)

    fig.update_layout(
        title="Interactive Stevens Step Sequence Plot",
        xaxis_title="Timestamp",
        yaxis_title="Sequence Number",
        legend_title="Legend",
        template="plotly_white",
        hovermode="x unified",
    )

    # Show the plot
    fig.show()


if __name__ == "__main__":
    sender = PcapFile(
        "traces/bandwidth_primary/baseline-udp/7438211/3.0Mbps/-TrafficSender0-1.pcap"
    )
    receiver = PcapFile(
        "traces/bandwidth_primary/baseline-udp/7438211/3.0Mbps/-Receiver-1.pcap"
    )

    sender_seq = Packets(
        "Sender Seq",
        sender.packets_from(SOURCE),
        operator.attrgetter("seq"),
        build_conditions(
            SingleDupAckRetransmitSackAnalyzer(sender),
            FastRetransmitSackAnalyzer(sender),
            FastRetransmissionAnalyzer(sender),
            DroppedPacketsAnalyzer(sender, receiver),
            source=SOURCE,
            destination=DESTINATION,
        ),
    )

    receiver_acks = Packets(
        "Receiver Ack",
        sender.packets_from(DESTINATION),
        operator.attrgetter("ack"),
    )

    plot_sequence(sender_seq, receiver_acks)
