from scapy.utils import rdpcap
from scapy.layers.inet import IP, TCP
import hypothesis

from tests.utils import FastReroutingUDPCommand


fast_rerouting_command = FastReroutingUDPCommand(seed=1, policy_threshold=50)


def check_not_empty(pcap_file):
    packets = rdpcap(pcap_file)
    assert len(packets) > 0


def check_out_of_order(pcap_file):
    packets = rdpcap(pcap_file)
    tcp_streams = (
        {}
    )  # Dictionary to store TCP streams by their unique 4-tuple (src, dst, sport, dport)

    for pkt in packets:
        if TCP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            seq = pkt[TCP].seq

            # Unique stream identifier
            stream_key = (src, dst, sport, dport)

            # Handle reverse direction for the same stream
            reverse_key = (dst, src, dport, sport)

            # Check the sequence numbers for out-of-order
            if stream_key in tcp_streams:
                last_seq = tcp_streams[stream_key]
                assert seq < last_seq
                tcp_streams[stream_key] = max(
                    last_seq, seq
                )  # Update last seen sequence
            elif reverse_key in tcp_streams:
                last_seq = tcp_streams[reverse_key]
                assert seq < last_seq
                tcp_streams[reverse_key] = max(
                    last_seq, seq
                )  # Update last seen sequence
            else:
                # First packet in the stream
                tcp_streams[stream_key] = seq


@hypothesis.given(
    bandwidth_access=hypothesis.strategies.integers(min_value=1, max_value=50),
    bandwidth_udp_access=hypothesis.strategies.integers(min_value=1, max_value=50),
    delay=hypothesis.strategies.integers(min_value=10, max_value=50),
)
@hypothesis.settings(deadline=None, max_examples=15)
def test_rerouting_head(bandwidth_access, bandwidth_udp_access, delay):
    dir = "traces/test_rerouting_head/"
    fast_rerouting_command(
        dir=dir,
        bandwidth_access=f"{bandwidth_access}KBps",
        bandwidth_primary=f"{(bandwidth_access + bandwidth_udp_access)// 2}KBps",
        bandwidth_udp_access=f"{bandwidth_udp_access}KBps",
        bandwidth_alternate="1000KBps",
        delay_primary=f"{delay}ms",
        delay_access="0ms",
        delay_alternate=f"{delay//2 - 1}ms",
        udp_start="15.0",
        tcp_bytes=bandwidth_access * 10_000 * 15,
    )
    check_out_of_order(f"{dir}-Receiver-1.pcap")
    check_not_empty(f"{dir}-Router01-3.pcap")
