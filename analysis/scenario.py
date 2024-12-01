from dataclasses import dataclass
from functools import cached_property, lru_cache
import os


import rich.progress

from analysis import discovery, statistic
from analysis.graph import Plot
from analysis.pcap import Communication, PcapFile


def _calculate_packet_loss(
    packets_at_source: int, packets_at_destination: int
) -> float:
    return 1 - (packets_at_destination / packets_at_source)


def extract_numerical_value_from_string(string: str) -> float:
    index = 0
    for index, character in enumerate(string):
        if not character.isdigit() and character != ".":
            break
    numerical_value = float(string[:index])
    return numerical_value


@dataclass(frozen=True)
class VariableRun:
    directory: str
    option: discovery.Options
    seed: discovery.Seed

    @property
    def path(self) -> str:
        return f"{self.directory}/{self.option}/{self.seed}"

    @lru_cache
    def pcap(self, variable: str, device: discovery.Devices, link: int) -> PcapFile:
        return PcapFile(f"{self.path}/{variable}/-{device}-{link}.pcap")

    def packet_loss_at(self, variable: str) -> float:
        addresses = self.ip_addresses(variable)
        source_pcap = self.pcap(variable, "TrafficSender0", 1)
        destination_pcap = self.pcap(variable, "Receiver", 1)
        source_packets = source_pcap.number_of_packets_from_source(addresses.source)
        destination_packets = destination_pcap.number_of_packets_from_source(
            addresses.source
        )
        return _calculate_packet_loss(source_packets, destination_packets)

    @cached_property
    def packet_loss(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    extract_numerical_value_from_string(variable),
                    self.packet_loss_at(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def variables(self) -> list[str]:
        return sorted(os.listdir(f"{self.directory}/{self.option}/{self.seed}"))

    @lru_cache
    def ip_addresses(self, variable: str) -> Communication:
        # TODO: replace with a method to handle multiple flows
        return self.pcap(variable, "TrafficSender0", 1).first_addresses

    @cached_property
    def plots(self) -> list[Plot]:
        plots = []
        for variable in self.variables:
            pcap = self.pcap(variable, "Receiver", 1)
            completion_time = pcap.flow_completion_time(*self.ip_addresses(variable))
            assert completion_time
            plots.append(
                Plot(extract_numerical_value_from_string(variable), completion_time)
            )
        return sorted(plots, key=lambda plot: plot.variable)


@dataclass(frozen=True)
class Scenario:
    directory: str
    option: discovery.Options
    seeds: list[discovery.Seed]

    @cached_property
    def runs(self) -> dict[discovery.Seed, VariableRun]:
        return {
            seed: VariableRun(self.directory, self.option, seed) for seed in self.seeds
        }

    @cached_property
    def times(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.plots
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    description=f"Calculating Times for {self.option}",
                )
            }
        )

    @cached_property
    def packet_loss(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.packet_loss
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    description=f"Calculating Packet Loss for {self.option}",
                )
            }
        )

    @cached_property
    def variables(self):
        assert self.runs
        runs = list(self.runs.values())
        return runs[0].variables
