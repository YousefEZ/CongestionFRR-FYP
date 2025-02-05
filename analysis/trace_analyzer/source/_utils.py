from scapy.all import Packet
from scapy.layers.inet import TCP

from analysis.trace_analyzer.source.socket_state import SackedByteRange


SMSS = 1446


def calculate_dropped_packets(sacks: list[SackedByteRange]) -> list[int]:
    dropped_packets = (
        dropped_packet
        for ranges in zip(sacks, sacks[1:])
        for dropped_packet in range(ranges[0][1], ranges[1][0], SMSS)
    )
    return list(dropped_packets)


def get_sacked_byte_ranges(packet: Packet) -> list[SackedByteRange]:
    sacks = dict(packet[TCP].options).get("SAck")
    if sacks is None:
        return []

    return sorted(
        [
            SackedByteRange(start=sacks[i], end=sacks[i + 1])
            for i in range(0, len(sacks), 2)
        ],
        key=lambda sacked_range: sacked_range.start,
    )


def calculate_sack_packets(sacked_bytes: list[SackedByteRange]) -> int:
    return sum([sack[1] - sack[0] for sack in sacked_bytes]) // SMSS
