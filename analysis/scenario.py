from typing import Literal, NamedTuple, NewType
from dataclasses import dataclass
from functools import cached_property, lru_cache
import os


import rich.progress
from scapy.all import rdpcap

from analysis.graph import Plot
from analysis.pcap import (
    Communication,
    calculate_number_of_packets_from_source,
    calculate_packet_loss,
    get_IP,
    get_flow_completion_time,
)


Seed = NewType("Seed", str)
Options = NewType("Options", str)

Devices = Literal[
    "Receiver", "TrafficSender", "Router01", "Router02", "Router03", "Receiver"
]


class PlotList(NamedTuple):
    variable: float
    times: list[float]


def _variance(times: list[float], average: float) -> float:
    return sum([(time - average) ** 2 for time in times]) / (len(times) - 1)


def extract_numerical_value_from_string(string: str) -> float:
    index = 0
    for index, character in enumerate(string):
        if not character.isdigit() and character != ".":
            break
    numerical_value = float(string[:index])
    return numerical_value


@dataclass(frozen=True)
class Run:
    directory: str
    option: Options
    seed: Seed

    @property
    def path(self) -> str:
        return f"{self.directory}/{self.option}/{self.seed}"

    def pcap_filename(self, variable: str, device: Devices, link: int) -> str:
        return f"{self.path}/{variable}/-{device}-{link}.pcap"

    @cached_property
    def packet_loss(self) -> float:
        loss = 0.0
        for variable in self.variables:
            source = self.ip_addresses(variable).source
            source_packets = calculate_number_of_packets_from_source(
                f"{self.directory}/{self.option}/{self.seed}/{variable}/-Sender-1.pcap",
                source,
            )
            destination_packets = calculate_number_of_packets_from_source(
                f"{self.directory}/{self.option}/{self.seed}/{variable}/-Receiver-1.pcap",
                source,
            )
            loss += calculate_packet_loss(source_packets, destination_packets)
        return loss / len(self.variables)

    @cached_property
    def variables(self) -> list[str]:
        return os.listdir(f"{self.directory}/{self.option}/{self.seed}")

    @lru_cache
    def ip_addresses(self, variable: str) -> Communication:
        path = self.pcap_filename(variable, "Receiver", 1)
        return get_IP(rdpcap(path))

    @cached_property
    def plots(self) -> list[Plot]:
        plots = []
        for variable in self.variables:
            path = self.pcap_filename(variable, "Receiver", 1)
            completion_time = get_flow_completion_time(
                path, self.ip_addresses(variable).destination
            )
            plots.append(
                Plot(extract_numerical_value_from_string(variable), completion_time)
            )
        return sorted(plots, key=lambda plot: plot.variable)


@dataclass(frozen=True)
class Scenario:
    directory: str
    option: Options
    seeds: list[Seed]

    @cached_property
    def runs(self) -> dict[Seed, Run]:
        return {seed: Run(self.directory, self.option, seed) for seed in self.seeds}

    @cached_property
    def times(self) -> dict[Seed, list[Plot]]:
        return {
            seed: scenario.plots
            for seed, scenario in rich.progress.track(
                self.runs.items(),
                description=f"Calculating Times for {self.option}",
            )
        }

    @cached_property
    def variables(self):
        return sorted([plot.variable for plot in list(self.times.values())[0]])

    @cached_property
    def plots(self) -> list[PlotList]:
        plot_lists = [PlotList(variable, []) for variable in self.variables]
        for times in self.times.values():
            for plot_list, seed_plot in zip(plot_lists, times):
                plot_list.times.append(seed_plot.time)
        return plot_lists

    @property
    def average(self) -> list[Plot]:
        assert self.times
        return [
            Plot(plot.variable, sum(plot.times) / len(plot.times))
            for plot in self.plots
        ]

    @property
    def variance(self) -> list[Plot]:
        assert self.times

        return [
            Plot(plot.variable, _variance(plot.times, average.time))
            for average, plot in zip(self.average, self.plots)
        ]

    @property
    def standard_deviation(self) -> list[Plot]:
        assert self.times

        return [
            Plot(plot.variable, variance.time**0.5)
            for variance, plot in zip(self.variance, self.plots)
        ]
