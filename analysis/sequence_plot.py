from typing import Callable
from scapy.layers.inet import TCP
import scapy.packet

from analysis.pcap import DESTINATION, SOURCE, PcapFile
import plotly.graph_objects as go
from analysis.trace_analyzer.source.regular_fast_retransmit import (
    FastRetransmissionAnalyzer,
)
from analysis.trace_analyzer.source.sack_fast_retransmit import (
    FastRetransmitSackAnalyzer,
)
from analysis.trace_analyzer.source.spurious_sack_fast_transmit import (
    SingleDupAckRetransmitSackAnalyzer,
)

PREMADE_COLORS = [
    "red",
    "blue",
    "green",
    "orange",
    "purple",
    "cyan",
    "magenta",
    "lime",
    "brown",
    "pink",
]


def assign_colour(assigned_colours: dict[str, str], condition: str) -> str:
    for colour in PREMADE_COLORS:
        if colour not in assigned_colours.values():
            assigned_colours[condition] = colour
            return colour
    assert False, "Too many conditions to plot, add more colours"


def get_highlighted_styles(
    data: list[scapy.packet.Packet],
    conditions: dict[str, list[scapy.packet.Packet]],
    assigned_colours: dict[str, str],
    default_color: str,
) -> tuple[list[str], list[int]]:
    """
    Generates lists of styles (colors and sizes) based on conditions for each packet.
    there is priority to what condition is matched first, dicts are ordered based on entry
    so higher precendece conditions should be placed first.

    Args:
        data (list[tuple[float, int, object]]): Sequence data.
        conditions (dict[str, callable]): Conditions to check.

    Returns:
        tuple[list[str], list[int]]: Marker colors and sizes.
    """
    colors = []
    sizes = []

    for condition in conditions:
        assign_colour(assigned_colours, condition)
    for packet in data:
        for condition, matched_set in conditions.items():
            if packet in matched_set:
                colors.append(assigned_colours[condition])
                sizes.append(10)
                break
        else:
            colors.append(default_color)
            sizes.append(4)
    return colors, sizes


def plot_sequence_plot(
    data: list[scapy.packet.Packet],
    classified: dict[str, list[scapy.packet.Packet]],
    origin: str,
    packet_repr_func: Callable[[scapy.packet.Packet], int],
    fig: go.Figure,
    assigned_colours: dict[str, str],
) -> None:
    origin_colour = assign_colour(assigned_colours, origin)
    colours, sizes = get_highlighted_styles(
        data, classified, assigned_colours, origin_colour
    )

    fig.add_trace(
        go.Scatter(
            x=[float(pkt.time) for pkt in data],
            y=[packet_repr_func(pkt) for pkt in data],
            mode="lines+markers",
            line_shape="hv",  # Step plot style
            name=origin,
            line=dict(color=origin_colour),
            marker=dict(color=colours, size=sizes),
            hovertemplate="Time: %{x}<br>Seq: %{y}<extra></extra>",
        )
    )
    for condition in classified:
        fig.add_trace(
            go.Scatter(
                x=[None],
                y=[None],
                mode="markers",
                marker=dict(color=assigned_colours[condition], size=10),
                name=f"{origin}: {condition}",
            )
        )


def plot_sequence(
    sender_data: list[scapy.packet.Packet],
    receiver_data: list[scapy.packet.Packet],
    sender_conditions: dict[str, list[scapy.packet.Packet]],
    receiver_conditions: dict[str, list[scapy.packet.Packet]],
) -> None:
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
    plot_sequence_plot(
        sender_data,
        sender_conditions,
        "Sender",
        lambda pkt: pkt[TCP].seq,
        fig,
        assigned_colours,
    )
    plot_sequence_plot(
        receiver_data,
        receiver_conditions,
        "Receiver",
        lambda pkt: pkt[TCP].ack,
        fig,
        assigned_colours,
    )

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

    fast_sack_retransmit = FastRetransmitSackAnalyzer(sender).filter_packets(
        SOURCE, DESTINATION
    )

    spurious_sack_fast_retransmit = SingleDupAckRetransmitSackAnalyzer(
        sender
    ).filter_packets(SOURCE, DESTINATION)

    fast_retransmit = [
        pkt
        for pkt in FastRetransmissionAnalyzer(sender).filter_packets(
            SOURCE, DESTINATION
        )
        if pkt not in fast_sack_retransmit
    ]

    plot_sequence(
        sender.packets_from(SOURCE),
        receiver.packets_from(DESTINATION),
        {
            "Fast Sack Retransmit": fast_sack_retransmit,
            "Single Dup Ack Retransmit": spurious_sack_fast_retransmit,
            "Fast Retransmit": fast_retransmit,
        },
        dict(),
    )
