from __future__ import annotations

import os
from dataclasses import dataclass
from functools import cached_property, lru_cache, wraps
from typing import Callable, Concatenate, Optional, ParamSpec

import pydantic
import rich.progress

from analysis import discovery, statistic
from analysis.graph import Plot
from analysis.pcap import Communication, PcapFile


P = ParamSpec("P")
console = rich.console.Console()


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
    variables: tuple[discovery.Variable, ...]

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
                    variable=extract_numerical_value_from_string(variable),
                    value=self.packet_loss_at(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def packet_reordering(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.pcap(
                        variable, "Receiver", 1
                    ).number_of_packet_reordering_from_source(
                        self.ip_addresses(variable).source
                    ),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

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
            assert completion_time, (
                f"Failed to calculate completion time for {variable}"
            )
            plots.append(
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=completion_time,
                )
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
        def wrapper(
            self: Scenario, *args: P.args, **kwargs: P.kwargs
        ) -> statistic.Statistic:
            if stat := self._load_statistic(property):
                console.print(
                    f":zap: [bold yellow]Loaded statistics[/bold yellow] for {self.option}'s {property} cache",
                    emoji=True,
                )
                return stat
            stat = func(self, *args, **kwargs)
            self._store_results(property, stat)
            return stat

        return wrapper

    return decorator


class CachedData(pydantic.BaseModel):
    data: dict[discovery.Seed, list[Plot]]


# TODO: simplify the storage of results mechanism, and allow for joining of multiple results
@dataclass(frozen=True)
class Scenario:
    directory: str
    option: discovery.Options
    seeds: list[discovery.Seed]
    variables: tuple[discovery.Variable, ...]

    @cached_property
    def path(self) -> str:
        return f"{self.directory}/{self.option}"

    @property
    def _cache_dir(self) -> str:
        return f".analysis_cache/{self.directory}/{self.option}"

    def _cache_file(self, property: str) -> str:
        return f"{self._cache_dir}_{property}.json"

    def _store_results(self, property: str, stat: statistic.Statistic) -> None:
        if not os.path.exists(self._cache_dir):
            os.makedirs(self._cache_dir)

        with open(self._cache_file(property), "w") as file:
            try:
                file.write(
                    CachedData.model_validate({"data": stat.data}).model_dump_json()
                )
            except Exception as e:
                console.print(
                    f":x:  [bold red]Failed[/bold red] to store results in cache for {property}: [bold red]{e}[/bold red]",
                )

    def _load_statistic(self, property: str) -> Optional[statistic.Statistic]:
        filename = self._cache_file(property)

        if not os.path.exists(filename):
            return None

        if os.path.getmtime(filename) < os.path.getmtime(self.path):
            os.remove(filename)
            return None

        with open(filename, "r") as cache_file:
            try:
                data = CachedData.model_validate_json(cache_file.read()).data
            except Exception as e:
                console.print(
                    f":x:  [bold red]Failed[/bold red] to load results from cache for {property}: [bold red]{e}[/bold red]",
                )
                os.remove(filename)
            else:
                if not set(self.seeds).issubset(set(data.keys())):
                    return None  # Cache is outdated

                numerical_variables = {
                    extract_numerical_value_from_string(variable)
                    for variable in self.variables
                }
                if any(
                    not numerical_variables.issubset(
                        {plot.variable for plot in data[seed]}
                    )
                    for seed in data
                ):
                    # missing variables
                    return None
                return statistic.Statistic(
                    {
                        discovery.Seed(seed): [
                            plot
                            for plot in data[seed]
                            if plot.variable in numerical_variables
                        ]
                        for seed in self.seeds
                    }
                )

        return None

    @cached_property
    def runs(self) -> dict[discovery.Seed, VariableRun]:
        return {
            seed: VariableRun(self.directory, self.option, seed, self.variables)
            for seed in self.seeds
        }

    @cached_property
    @_cache_statistic("times")
    def times(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.plots
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating Times for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("packet_loss")
    def packet_loss(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.packet_loss
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating Packet Loss for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("reordering")
    def reordering(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.packet_reordering
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating Packet Reordering for {self.option}",
                )
            }
        )
