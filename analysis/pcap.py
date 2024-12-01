from typing import NamedTuple
from scapy.all import rdpcap
from scapy.layers.inet import TCP, IP, PacketList

SOURCE = "10.1.2.1"
DESTINATION = "10.1.6.2"


class Communication(NamedTuple):
    source: str
    destination: str


def get_IP(packets: PacketList) -> Communication:
    return Communication(packets[0][IP].src, packets[0][IP].dst)


def flow_completion_time(packets: PacketList, destination: str) -> float:
    """Get the flow completion time of the TCP connection from the packets by checking the FIN-ACK flag."""
    TCP_FIN = 0x01
    TCP_ACK = 0x10

    for pkt in packets:
        if TCP in pkt:
            sender, _ = pkt.getlayer("IP").src, pkt.getlayer("IP").dst
            if (
                sender == destination
                and pkt[TCP].flags & TCP_FIN
                and pkt[TCP].flags & TCP_ACK
            ):
                return pkt.time
    assert False, "Flow completion time not found"


def get_flow_completion_time(filename: str, destination: str) -> float:
    packets = rdpcap(filename)
    return flow_completion_time(packets, destination)


def calculate_number_of_packets_from_source(filename: str, source: str) -> int:
    packets = rdpcap(filename)
    return len(list(filter(lambda pkt: TCP in pkt and pkt[IP].src == source, packets)))


def calculate_packet_loss(packets_at_source: int, packets_at_destination: int) -> float:
    return 1 - (packets_at_destination / packets_at_source)
