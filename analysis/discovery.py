import os
from typing import Literal, NewType, cast

Devices = Literal[
    "Receiver", "TrafficSender0", "Router01", "Router02", "Router03", "Receiver"
]
Seed = NewType("Seed", str)
Variable = NewType("Variable", str)
Options = Literal["baseline", "baseline-udp", "frr", "frr-udp"]


# expected directory structure
# traces/"options"/"seed-run"/"variable"
# options being "baseline", "baseline-udp", "frr", "frr-udp" etc.
# seed-run being "1234-1", "1234-2", "1234-3", "345-1", "345-2", "345-3"
# variable being the values such as 1.25Mbps, 2.5Mbps, 5Mbps, 10Mbps, 20Mbps, 40Mbps


def discover_variables(directory: str, option: str, seed: str) -> list[Variable]:
    return list(map(Variable, sorted(os.listdir(f"{directory}/{option}/{seed}"))))


def discover_seeds(directory: str, option: str) -> list[Seed]:
    return list(map(Seed, os.listdir(f"{directory}/{option}")))


def discover_options(directory: str) -> list[Options]:
    return cast(list[Options], list(os.listdir(directory)))


def discover_tcp_hosts(directory: str, option: str, seed: str) -> list[str]:
    return list(
        filter(
            lambda device: "TrafficSender" in device,
            os.listdir(f"{directory}/{option}/{seed}"),
        )
    )
