import os

from . import scenario

# expected directory structure
# traces/"options"/"seed-run"/"variable"
# options being "baseline", "baseline-udp", "frr", "frr-udp" etc.
# seed-run being "1234-1", "1234-2", "1234-3", "345-1", "345-2", "345-3"
# variable being the values such as 1.25Mbps, 2.5Mbps, 5Mbps, 10Mbps, 20Mbps, 40Mbps


def discover_seeds(directory: str, option: str) -> list[scenario.Seed]:
    return list(map(scenario.Seed, os.listdir(f"{directory}/{option}")))


def discover_options(directory: str) -> list[scenario.Options]:
    return list(map(scenario.Options, os.listdir(directory)))
