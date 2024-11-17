import os

import scapy.utils


class FastReroutingUDPCommand:
    def __init__(self, *, policy_threshold, seed):
        self.policy_threshold = policy_threshold
        self.seed = seed

    def __call__(self, dir: str, **variables):
        os.environ["NS_LOG"] = "FRRQueue=info|prefix_time"
        command = (
            [
                "./ns3",
                "run",
                '"scratch/combined-frr.cc',
                "--tcp_senders=1",
                f"--policy_threshold={self.policy_threshold}",
                f"--dir={dir}",
                f"--seed={self.seed}",
            ]
            + [f"--{key}={value}" for key, value in variables.items()]
            + ['"']
        )

        print(f"Running command: {' '.join(command)}")
        # execute
        os.system(" ".join(command))
        # subprocess.run(command, shell=True, check=True)


fast_rerouting_udp_command = FastReroutingUDPCommand(policy_threshold=50, seed=1)


def test_no_congestion_no_rerouting():
    dir = "traces/test_no_congestion_no_rerouting/"
    fast_rerouting_udp_command(
        dir=dir,
        bandwidth_primary="5KBps",
        bandwidth_access="2KBps",
        bandwidth_udp_access="2KBps",
    )
    assert not list(scapy.utils.PcapReader(f"{dir}-Router03-1.pcap"))
