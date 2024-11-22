import scapy.utils
import hypothesis
from tests.utils import FastReroutingUDPCommand


fast_rerouting_udp_command = FastReroutingUDPCommand(policy_threshold=50, seed=1)


@hypothesis.given(
    bandwidth_access=hypothesis.strategies.integers(min_value=1, max_value=100),
    bandwidth_udp_access=hypothesis.strategies.integers(min_value=1, max_value=100),
)
@hypothesis.settings(deadline=None, max_examples=15)
def test_no_congestion_no_rerouting(bandwidth_access, bandwidth_udp_access):
    dir = "traces/test_no_congestion_no_rerouting/"
    fast_rerouting_udp_command(
        dir=dir,
        bandwidth_primary=f"{bandwidth_access + bandwidth_udp_access + 1}KBps",
        bandwidth_access=f"{bandwidth_access}KBps",
        bandwidth_udp_access=f"{bandwidth_udp_access}KBps",
    )
    assert not list(scapy.utils.PcapReader(f"{dir}-Router03-1.pcap"))
