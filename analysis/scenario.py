from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import cached_property, lru_cache, wraps
from typing import Callable, Concatenate, Optional, ParamSpec, override


import pydantic
import rich.progress
import scapy.packet

from analysis import discovery, statistic
from analysis.graph import T, Plot
from analysis.pcap import Communication, PcapFile
from analysis.trace_analyzer.dst.reordered_packets import (
    DroppedRetransmittedPacketCapture,
    SpuriousOOORTOCapture,
    SpuriousRetransmissionAnalyzer,
    congestion_windows,
    hashable_packet,
)
from analysis.trace_analyzer.source.packet_capture import PacketCapture
from analysis.trace_analyzer.source.replayer import TcpSourceReplayer
from analysis.trace_analyzer.source.socket_state import SocketState
from analysis.trace_analyzer.source.spurious_sack_fast_transmit import (
    TotalTimeInRecovery,
)


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
            return float(string[:index])
    else:
        return float(string)


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
class WaitTimeAfterRTO(PacketCapture):
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
    def pcap(
        self, variable: discovery.Variable, device: discovery.Devices, link: int
    ) -> PcapFile:
        return PcapFile(f"{self.path}/{variable}/-{device}-{link}.pcap")

    @cached_property
    def number_of_senders(self) -> int:
        return len(next(iter(self.senders.values())))

    @cached_property
    def senders(self) -> dict[discovery.Variable, list[PcapFile]]:
        return {
            variable: [
                PcapFile(os.path.join(self.path, variable, file))
                for file in discovery.discover_senders(
                    self.directory, self.option, self.seed, variable
                )
            ]
            for variable in self.variables
        }

    @property
    def receivers(self) -> dict[discovery.Variable, PcapFile]:
        return {
            variable: self.pcap(variable, "Receiver", 1) for variable in self.variables
        }

    def debug_filename(self, variable: str) -> str:
        return f"{self.path}/{variable}/debug.log"

    def cwnd_filename(self, variable: str, sender: int) -> str:
        return f"{self.path}/{variable}/n{sender}.dat"

    def packet_loss_at(self, variable: str) -> float:
        addresses = self.ip_addresses(variable)
        source_pcap = self.pcap(variable, "TrafficSender0", 1)
        destination_pcap = self.pcap(variable, "Receiver", 1)
        source_packets = source_pcap.number_of_packets_from_source(addresses.source)
        destination_packets = destination_pcap.number_of_packets_from_source(
            addresses.source
        )
        return _calculate_packet_loss(source_packets, destination_packets)

    def calculate_average_congestion_window(self, variable: str, sender: int) -> float:
        # [(0, 10), (1, 20), (2, 30)] => (10 + 20) / 2 = 15
        cwnds = congestion_windows(self.cwnd_filename(variable, sender))
        return (
            sum(
                (second[0] - first[0]) * first[1]
                for first, second in zip(cwnds, cwnds[1:])
            )
            / cwnds[-1][0]
        )

    def calculate_rto_wait_time_for_unsent(self, variable: str) -> float:
        capture = RTOWaitingForUnsent()
        TcpSourceReplayer(
            self.pcap(variable, "TrafficSender0", 1),
            *self.ip_addresses(variable),
            capture,
        ).run()
        return capture.wait_time

    def calculate_rto_wait_time(self, variable: str) -> float:
        capture = WaitTimeAfterRTO()
        TcpSourceReplayer(
            self.pcap(variable, "TrafficSender0", 1),
            *self.ip_addresses(variable),
            capture,
        ).run()
        return capture.wait_time

    def calculate_recovery_time(self, variable: str) -> float:
        capture = TotalTimeInRecovery()
        TcpSourceReplayer(
            self.pcap(variable, "TrafficSender0", 1),
            *self.ip_addresses(variable),
            capture,
        ).run()
        return capture.total_time_in_recovery

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
        rerouted_pcap = self.pcap(variable, "Router03", 2)
        return rerouted_pcap.number_of_packets_from_source(addresses.source)

    @lru_cache
    def udp_packets_rerouted_at(self, variable: str) -> int:
        rerouted_pcap = self.pcap(variable, "Router03", 2)
        number_rerouted = len(rerouted_pcap.udp_packets)
        return number_rerouted

    @lru_cache
    def udp_packets_rerouted_percentage_at(self, variable: str) -> float:
        udp_packets_sent = len(self.pcap(variable, "CongestionSender", 1).packets)
        if udp_packets_sent == 0:
            return 0.0
        return (self.udp_packets_rerouted_at(variable) / udp_packets_sent) * 100

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

    def _map_plots(self, method: Callable[[str], T]) -> list[Plot[T]]:
        return sorted(
            (
                Plot(
                    variable=extract_numerical_value_from_string(variable),
                    value=method(variable),
                )
                for variable in self.variables
            ),
            key=lambda plot: plot.variable,
        )

    def packet_rerouted(self) -> list[Plot]:
        return self._map_plots(self.packets_rerouted_at)

    def packet_rerouted_percentage(self) -> list[Plot]:
        return self._map_plots(self.packets_rerouted_percentage_at)

    def spurious_retransmissions(self) -> list[Plot]:
        return self._map_plots(
            lambda variable: len(
                SpuriousRetransmissionAnalyzer(
                    self.pcap(variable, "TrafficSender0", 1),
                    self.pcap(variable, "Receiver", 1),
                ).filter_packets(*self.ip_addresses(variable))
            )
        )

    def spurious_retransmissions_from_reordering(self) -> list[Plot]:
        return self._map_plots(self.calculate_spurious_retransmissions_from_reordering)

    def longest_number_of_packets_spuriously_retransmitted_before_rto(
        self,
    ) -> list[Plot]:
        return self._map_plots(
            self.calculate_longest_number_of_packets_spuriously_retransmitted_before_rto
        )

    def packet_loss(self) -> list[Plot]:
        return self._map_plots(self.packet_loss_at)

    def packets_lost(self) -> list[Plot]:
        return self._map_plots(self.packets_lost_at)

    def udp_lost(self) -> list[Plot]:
        return self._map_plots(self.udp_packets_lost_at)

    def udp_loss(self) -> list[Plot]:
        return self._map_plots(self.udp_packets_loss_at)

    def udp_rerouted(self) -> list[Plot]:
        return self._map_plots(self.udp_packets_rerouted_at)

    def udp_rerouted_percentage(self) -> list[Plot]:
        return self._map_plots(self.udp_packets_rerouted_percentage_at)

    def packet_reordering(self) -> list[Plot]:
        return self._map_plots(
            lambda variable: self.pcap(
                variable, "Receiver", 1
            ).number_of_packet_reordering_from_source(
                self.ip_addresses(variable).source
            )
        )

    def total_time_in_recovery(self) -> list[Plot]:
        return self._map_plots(self.calculate_recovery_time)

    def rto_wait_time_for_unsent(self) -> list[Plot]:
        return self._map_plots(self.calculate_rto_wait_time_for_unsent)

    def rto_wait_time(self) -> list[Plot]:
        return self._map_plots(self.calculate_rto_wait_time)

    def dropped_retransmitted_packets(self) -> list[Plot]:
        return self._map_plots(self.calculate_dropped_retransmitted_packets)

    @lru_cache
    def ip_addresses(self, variable: discovery.Variable) -> Communication:
        # TODO: replace with a method to handle multiple flows
        return self.pcap(variable, "TrafficSender0", 1).first_addresses

    def time(self) -> list[Plot]:
        return self._map_plots(
            lambda variable: self.pcap(variable, "Receiver", 1).flow_completion_time(
                *self.ip_addresses(variable)
            )
        )

    def average_congestion_window(self) -> list[Plot]:
        return self._map_plots(
            lambda variable: self.calculate_average_congestion_window(variable, 0)
        )

    @lru_cache
    def flow_ip_addresses(self, variable: discovery.Variable) -> list[Communication]:
        results = [sender.first_addresses for sender in self.senders[variable]]
        return results

    def time_multi_flow(self) -> list[Plot]:
        return self._map_plots(
            lambda variable: [
                self.pcap(variable, "Receiver", 1).flow_completion_time(*ip_addresses)
                for ip_addresses in self.flow_ip_addresses(variable)
            ]
        )

    def average_time(self) -> list[Plot]:
        ip_addresses = self.ip_addresses(self.variables[0])

        return self._map_plots(
            lambda variable: sum(
                self.pcap(variable, "Receiver", 1)
                .flow_completion_times(ip_addresses.destination)
                .values()
            )
            / self.number_of_senders
        )

    def max_flow_time(self) -> list[Plot]:
        ip_addresses = self.ip_addresses(self.variables[0])

        return self._map_plots(
            lambda variable: max(
                self.pcap(variable, "Receiver", 1)
                .flow_completion_times(ip_addresses.destination)
                .values()
            )
        )


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

    def _map_statistic(
        self, method: Callable[[VariableRun], list[Plot]]
    ) -> statistic.Statistic:
        return statistic.Statistic(
            {
                seed: method(run)
                for seed, run in rich.progress.track(
                    self.runs.items(),
                    console=console,
                    description=f"Calculating {method.__name__} for {self.option}",
                )
            }
        )

    @cached_property
    @_cache_statistic("average_time")
    def average_time(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.average_time)

    @cached_property
    @_cache_statistic("max_flow_time")
    def max_flow_time(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.max_flow_time)

    @cached_property
    @_cache_statistic("times")
    def times(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.time)

    @cached_property
    @_cache_statistic("times_multi_flow")
    def times_multi_flow(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.time_multi_flow)

    @cached_property
    @_cache_statistic("packets_lost")
    def packets_lost(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.packets_lost)

    @cached_property
    @_cache_statistic("udp_loss")
    def udp_loss(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.udp_lost)

    @cached_property
    @_cache_statistic("_udp_rerouted")
    def udp_rerouted(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.udp_rerouted)

    @cached_property
    @_cache_statistic("_udp_rerouted_percentage")
    def udp_rerouted_percentage(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.udp_rerouted_percentage)

    @cached_property
    @_cache_statistic("udp_lost")
    def udp_lost(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.udp_loss)

    @cached_property
    @_cache_statistic("packet_loss")
    def packet_loss(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.packet_loss)

    @cached_property
    @_cache_statistic("reordering")
    def reordering(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.packet_reordering)

    @cached_property
    @_cache_statistic("rerouted")
    def rerouted(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.packet_rerouted)

    @cached_property
    @_cache_statistic("rerouted_percentage")
    def rerouted_percentage(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.packet_rerouted_percentage)

    @cached_property
    @_cache_statistic("spurious_retransmissions")
    def spurious_retransmissions(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.spurious_retransmissions)

    @cached_property
    @_cache_statistic("spurious_retransmission_from_reordering")
    def spurious_retransmissions_from_reordering(
        self,
    ) -> statistic.Statistic:
        return self._map_statistic(VariableRun.spurious_retransmissions_from_reordering)

    @cached_property
    @_cache_statistic("longest_spurious_retransmissions_before_rto")
    def longest_number_of_packets_spuriously_retransmitted_before_rto(
        self,
    ) -> statistic.Statistic:
        return self._map_statistic(
            VariableRun.longest_number_of_packets_spuriously_retransmitted_before_rto
        )

    @cached_property
    @_cache_statistic("rto_wait_time")
    def rto_wait_time(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.rto_wait_time)

    @cached_property
    @_cache_statistic("dropped_retransmitted_packets")
    def dropped_retransmitted_packets(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.dropped_retransmitted_packets)

    @cached_property
    @_cache_statistic("rto_wait_time_for_unsent")
    def rto_wait_time_for_unsent(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.rto_wait_time_for_unsent)

    @cached_property
    @_cache_statistic("average_congestion_window")
    def average_congestion_window(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.average_congestion_window)

    @cached_property
    @_cache_statistic("total_recovery_time")
    def total_recovery_time(self) -> statistic.Statistic:
        return self._map_statistic(VariableRun.total_time_in_recovery)
