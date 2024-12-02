from __future__ import annotations

import os
import csv
from dataclasses import dataclass
from functools import cached_property, lru_cache, wraps
from typing import Callable, Concatenate, Optional, ParamSpec

import rich.progress

from analysis import discovery, statistic
from analysis.graph import Plot
from analysis.pcap import Communication, PcapFile


P = ParamSpec("P")


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


def _cache_statistic(
    property: str,
) -> Callable[
    [Callable[Concatenate[Scenario, P], statistic.Statistic]],
    Callable[Concatenate[Scenario, P], statistic.Statistic],
]:
    def decorator(
        func: Callable[Concatenate[Scenario, P], statistic.Statistic],
    ) -> Callable[Concatenate[Scenario, P], statistic.Statistic]:
        @wraps(func)
        def wrapper(self, *args: P.args, **kwargs: P.kwargs) -> statistic.Statistic:
            if stat := self._load_statistic(property):
                return stat
            stat = func(self, *args, **kwargs)
            self._store_results(property, stat)
            return stat

        return wrapper

    return decorator


@dataclass(frozen=True)
class Scenario:
    directory: str
    option: discovery.Options
    seeds: list[discovery.Seed]

    @cached_property
    def path(self) -> str:
        return f"{self.directory}/{self.option}"

    def _store_results(self, property: str, stat: statistic.Statistic) -> None:
        with open(f"{self.path}/.{property}.csv", "w") as file:
            writer = csv.DictWriter(file, fieldnames=["seed", "variable", "value"])
            writer.writerow({"seed": "seed", "variable": "variable", "value": "value"})
            for seed, plots in stat.data.items():
                for plot in plots:
                    writer.writerow(
                        {"seed": seed, "variable": plot.variable, "value": plot.time}
                    )

    def _load_statistic(self, property: str) -> Optional[statistic.Statistic]:
        if not os.path.exists(f"{self.path}/.{property}.csv"):
            return None

        with open(f"{self.path}/.{property}.csv", "r") as file:
            reader = csv.DictReader(file)
            data = {}
            for row in reader:
                seed = row["seed"]
                variable = row["variable"]
                value = row["value"]
                if seed not in data:
                    data[seed] = []
                data[seed].append(Plot(float(variable), float(value)))
            return statistic.Statistic(data)

    @cached_property
    def runs(self) -> dict[discovery.Seed, VariableRun]:
        return {
            seed: VariableRun(self.directory, self.option, seed) for seed in self.seeds
        }

    @cached_property
    @_cache_statistic("times")
    def times(self) -> statistic.Statistic:
        if stat := self._load_statistic("times"):
            return stat
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
    @_cache_statistic("packet_loss")
    def packet_loss(self) -> statistic.Statistic:
        if stat := self._load_statistic("packet_loss"):
            return stat
        stat = statistic.Statistic(
            {
                seed: scenario.packet_loss
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    description=f"Calculating Packet Loss for {self.option}",
                )
            }
        )
        self._store_results("packet_loss", stat)
        return stat

    @cached_property
    def variables(self):
        assert self.runs
        runs = list(self.runs.values())
        return runs[0].variables
