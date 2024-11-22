import os


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
