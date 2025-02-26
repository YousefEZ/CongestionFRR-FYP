from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import cached_property, lru_cache, wraps
from typing import Callable, Concatenate, Optional, ParamSpec, override


import pydantic
import rich.progress
import scapy.packet

from analysis import discovery, statistic
from analysis.graph import Plot
from analysis.pcap import Communication, PcapFile
from analysis.trace_analyzer.dst.reordered_packets import (
    DroppedRetransmittedPacketCapture,
    RTOCounterCapture,
    RecoveryTimeCapture,
    SpuriousOOORTOCapture,
    SpuriousRetransmissionAnalyzer,
    average_congestion_window,
    congestion_windows,
    hashable_packet,
)
from analysis.trace_analyzer.source.packet_capture import PacketCapture
from analysis.trace_analyzer.source.replayer import TcpSourceReplayer
from analysis.trace_analyzer.source.socket_state import SocketState


P = ParamSpec("P")
console = rich.console.Console()


def _calculate_packet_loss(
    packets_at_source: int, packets_at_destination: int
) -> float:
    return (1 - (packets_at_destination / packets_at_source)) * 100


def extract_numerical_value_from_string(string: str) -> float:
    index = 0
    for index, character in enumerate(string):
        if not character.isdigit() and character != ".":
            break
    else:
        return float(string)
    numerical_value = float(string[:index])
    return numerical_value


@dataclass
class RTOWaitingForUnsent(PacketCapture):
    wait_time: float = field(default_factory=float)

    @override
    def on_retransmission_timeout(
        self, packet: scapy.packet.Packet, state: SocketState
    ) -> None:
        if state.high_tx_mark < 997_000:
            self.wait_time += float(packet.time) - state.last_send_timestamp


@dataclass
class RTOWaitTime(PacketCapture):
    wait_time: float = field(default_factory=float)

    @override
    def on_retransmission_timeout(
        self, packet: scapy.packet.Packet, state: SocketState
    ) -> None:
        self.wait_time += float(packet.time) - state.last_send_timestamp


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

    @property
    def senders(self) -> dict[discovery.Variable, PcapFile]:
        return {
            variable: self.pcap(variable, "TrafficSender0", 1)
            for variable in self.variables
        }

    @property
    def receivers(self) -> dict[discovery.Variable, PcapFile]:
        return {
            variable: self.pcap(variable, "Receiver", 1) for variable in self.variables
        }

    def debug_filename(self, variable: str) -> str:
        return f"{self.path}/{variable}/debug.log"

    def cwnd_filename(self, variable: str) -> str:
        return f"{self.path}/{variable}/n0.dat"

    def packet_loss_at(self, variable: str) -> float:
        addresses = self.ip_addresses(variable)
        source_pcap = self.pcap(variable, "TrafficSender0", 1)
        destination_pcap = self.pcap(variable, "Receiver", 1)
        source_packets = source_pcap.number_of_packets_from_source(addresses.source)
        destination_packets = destination_pcap.number_of_packets_from_source(
            addresses.source
        )
        return _calculate_packet_loss(source_packets, destination_packets)

    def calculate_number_of_rtos(self, variable: str) -> int:
        capture = RTOCounterCapture()
        TcpSourceReplayer(
            self.pcap(variable, "TrafficSender0", 1),
            *self.ip_addresses(variable),
            capture,
        ).run()
        return capture.rto_count

    def calculate_rto_wait_time_for_unsent(self, variable: str) -> float:
        capture = RTOWaitingForUnsent()
        TcpSourceReplayer(
            self.pcap(variable, "TrafficSender0", 1),
            *self.ip_addresses(variable),
            capture,
        ).run()
        return capture.wait_time

    def calculate_rto_wait_time(self, variable: str) -> float:
        print(f"Calculating RTO wait time for {variable} @ seed={self.seed}")
        capture = RTOWaitTime()
        TcpSourceReplayer(
            self.pcap(variable, "TrafficSender0", 1),
            *self.ip_addresses(variable),
            capture,
        ).run()
        return capture.wait_time

    @lru_cache
    def packets_sent_by_source(self, variable: str) -> int:
        source_pcap = self.pcap(variable, "TrafficSender0", 1)
        return source_pcap.number_of_packets_from_source(
            self.ip_addresses(variable).source
        )

    def packets_lost_at(self, variable: str) -> int:
        addresses = self.ip_addresses(variable)
        destination_pcap = self.pcap(variable, "Receiver", 1)
        destination_packets = destination_pcap.number_of_packets_from_source(
            addresses.source
        )
        return self.packets_sent_by_source(variable) - destination_packets

    def udp_packets_lost_at(self, variable: str) -> int:
        sent = len(self.pcap(variable, "CongestionSender", 1).packets)
        received = len(self.pcap(variable, "Receiver", 1).udp_packets)
        return sent - received

    def udp_packets_loss_at(self, variable: str) -> float:
        sent = len(self.pcap(variable, "CongestionSender", 1).packets)
        if sent == 0:
            return 0.0
        received = len(self.pcap(variable, "Receiver", 1).udp_packets)
        return _calculate_packet_loss(sent, received)

    @lru_cache
    def packets_rerouted_at(self, variable: str) -> int:
        addresses = self.ip_addresses(variable)
        rerouted_pcap = self.pcap(variable, "Router03", 1)
        return rerouted_pcap.number_of_packets_from_source(addresses.source)

    @lru_cache
    def udp_packets_rerouted_at(self, variable: str) -> int:
        rerouted_pcap = self.pcap(variable, "Router03", 1)
        number_rerouted = len(rerouted_pcap.udp_packets)
        return number_rerouted

    @lru_cache
    def udp_packets_rerouted_percentage_at(self, variable: str) -> float:
        udp_packets_sent = len(self.pcap(variable, "CongestionSender", 1).packets)
        if udp_packets_sent == 0:
            return 0.0
        return (self.udp_packets_rerouted_at(variable) / udp_packets_sent) * 100

    def calculate_average_cwnd(self, variable: str) -> float:
        return average_congestion_window(
            congestion_windows(self.cwnd_filename(variable))
        )

    def calculate_recovery_time(self, variable: str) -> float:
        capture = RecoveryTimeCapture()
        TcpSourceReplayer(
            self.pcap(variable, "TrafficSender0", 1),
            *self.ip_addresses(variable),
            capture,
        ).run()
        return capture.recovery_time

    def calculate_dropped_retransmitted_packets(self, variable: str) -> int:
        dropped_packets_capture = DroppedRetransmittedPacketCapture()
        TcpSourceReplayer(
            self.pcap(variable, "TrafficSender0", 1),
            *self.ip_addresses(variable),
            dropped_packets_capture,
        ).run()
        return len(dropped_packets_capture.dropped_packets)

    def packets_rerouted_percentage_at(self, variable: str) -> float:
        return (
            self.packets_rerouted_at(variable) / self.packets_sent_by_source(variable)
        ) * 100

    def calculate_longest_number_of_packets_spuriously_retransmitted_before_rto(
        self, variable: str
    ) -> int:
        spur_ooo_packets = SpuriousRetransmissionAnalyzer(
            self.pcap(variable, "TrafficSender0", 1),
            self.pcap(variable, "Receiver", 1),
        ).filter_packets(*self.ip_addresses(variable))

        burst_capture = SpuriousOOORTOCapture(
            spurious_ooo_packets=[hashable_packet(p) for p in spur_ooo_packets]
        )
        TcpSourceReplayer(
            self.pcap(variable, "TrafficSender0", 1),
            *self.ip_addresses(variable),
            burst_capture,
        ).run()

        return burst_capture.longest_spurious_ooo_burst_count

    def calculate_spurious_retransmissions_from_reordering(self, variable: str) -> int:
        spur_ooo_packets = SpuriousRetransmissionAnalyzer(
            self.pcap(variable, "TrafficSender0", 1),
            self.pcap(variable, "Receiver", 1),
        ).filter_packets(*self.ip_addresses(variable))

        burst_capture = SpuriousOOORTOCapture(
            spurious_ooo_packets=[hashable_packet(p) for p in spur_ooo_packets]
        )
        TcpSourceReplayer(
            self.pcap(variable, "TrafficSender0", 1),
            *self.ip_addresses(variable),
            burst_capture,
        ).run()

        return burst_capture.longest_spurious_ooo_burst_count

    @cached_property
    def packet_rerouted(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.packets_rerouted_at(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def packet_rerouted_percentage(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.packets_rerouted_percentage_at(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def spurious_retransmissions(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=len(
                        SpuriousRetransmissionAnalyzer(
                            self.pcap(variable, "TrafficSender0", 1),
                            self.pcap(variable, "Receiver", 1),
                        ).filter_packets(*self.ip_addresses(variable))
                    ),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def average_congestion_window(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.calculate_average_cwnd(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def rto_count(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.calculate_number_of_rtos(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def spurious_retransmissions_from_reordering(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.calculate_spurious_retransmissions_from_reordering(
                        variable
                    ),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def longest_number_of_packets_spuriously_retransmitted_before_rto(
        self,
    ) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.calculate_longest_number_of_packets_spuriously_retransmitted_before_rto(
                        variable
                    ),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

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
    def packets_lost(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.packets_lost_at(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def udp_lost(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.udp_packets_lost_at(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def udp_loss(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.udp_packets_loss_at(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def udp_rerouted(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.udp_packets_rerouted_at(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def udp_rerouted_percentage(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.udp_packets_rerouted_percentage_at(variable),
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

    @cached_property
    def rto_wait_time_for_unsent(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.calculate_rto_wait_time_for_unsent(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def recovery_time(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.calculate_recovery_time(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def rto_wait_time(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.calculate_rto_wait_time(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    @cached_property
    def dropped_retransmitted_packets(self) -> list[Plot]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=self.calculate_dropped_retransmitted_packets(variable),
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
    @_cache_statistic("packets_lost")
    def packets_lost(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.packets_lost
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating Packets Lost for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("udp_loss")
    def udp_loss(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.udp_loss
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating UDP Lost for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("_udp_rerouted")
    def udp_rerouted(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.udp_rerouted
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating UDP Rerouted for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("_udp_rerouted_percentage")
    def udp_rerouted_percentage(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.udp_rerouted_percentage
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating UDP Rerouted Percentage for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("udp_lost")
    def udp_lost(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.udp_lost
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating UDP Lost for {self.option}",
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

    @cached_property
    @_cache_statistic("rerouted")
    def rerouted(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.packet_rerouted
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating Packet Rerouting for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("rerouted_percentage")
    def rerouted_percentage(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.packet_rerouted_percentage
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating Packet Rerouting Percentage for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("spurious_retransmissions")
    def spurious_retransmissions(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.spurious_retransmissions
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating Spurious Retransmissions for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("spurious_retransmission_from_reordering")
    def spurious_retransmissions_from_reordering(
        self,
    ) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.spurious_retransmissions_from_reordering
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating Spurious Retransmissions Reordered for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("longest_spurious_retransmissions_before_rto")
    def longest_number_of_packets_spuriously_retransmitted_before_rto(
        self,
    ) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.longest_number_of_packets_spuriously_retransmitted_before_rto
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating Spurious Retransmissions Reordered for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("rto_wait_time")
    def rto_wait_time(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.rto_wait_time
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating RTO Wait Time for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("dropped_retransmitted_packets")
    def dropped_retransmitted_packets(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.dropped_retransmitted_packets
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating Dropped Retransmitted Packets for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("rto_wait_time_for_unsent")
    def rto_wait_time_for_unsent(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.rto_wait_time_for_unsent
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating RTO Wait Time for Unsent Packets for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("rto_count")
    def rto_count(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.rto_count
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating RTO Count for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("recovery_time")
    def recovery_time(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.recovery_time
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating Recovery Time for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("average_congestion_window")
    def average_congestion_window(self) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: scenario.average_congestion_window
                for seed, scenario in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating Average Congestion Window for {self.option}",
                )
            }
        )
