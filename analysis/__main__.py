from dataclasses import dataclass
from functools import cached_property
import os

from typing import NamedTuple, NewType, Optional
import click
import rich.progress
from scapy.all import rdpcap


from analysis.graph import Plot, plot_flow_completion_time
from analysis.pcap import get_IP, get_flow_completion_time


# expected directory structure
# traces/"options"/"seed-run"/"variable"
# options being "baseline", "baseline-udp", "frr", "frr-udp" etc.
# seed-run being "1234-1", "1234-2", "1234-3", "345-1", "345-2", "345-3"
# variable being the values such as 1.25Mbps, 2.5Mbps, 5Mbps, 10Mbps, 20Mbps, 40Mbps

Seed = NewType("Seed", str)
Options = NewType("Options", str)


def extract_numerical_value_from_string(string: str) -> float:
    index = 0
    for index, character in enumerate(string):
        if not character.isdigit() and character != ".":
            break
    numerical_value = float(string[:index])
    return numerical_value


def discover_variables(traces: str, option: Options, seed: Seed) -> list[str]:
    return os.listdir(f"{traces}/{option}/{seed}")


def get_destination_ip_address(
    traces: str, option: Options, seed: Seed, variable: str
) -> str:
    path = f"{traces}/{option}/{seed}/{variable}/-Receiver-1.pcap"

    return get_IP(rdpcap(path)).destination


def calculate_plots(traces: str, option: Options, seed: Seed) -> list[Plot]:
    plots = []
    for variable in discover_variables(traces, option, seed):
        path = f"{traces}/{option}/{seed}/{variable}/-Receiver-1.pcap"
        completion_time = get_flow_completion_time(
            path, get_destination_ip_address(traces, option, seed, variable)
        )
        plots.append(
            Plot(extract_numerical_value_from_string(variable), completion_time)
        )
    plots = sorted(plots, key=lambda plot: plot.variable)
    return plots


class PlotList(NamedTuple):
    variable: float
    times: list[float]


def _variance(times: list[float], average: float) -> float:
    return sum([(time - average) ** 2 for time in times]) / (len(times) - 1)


@dataclass(frozen=True)
class FlowCompletionTimes:
    directory: str
    option: Options
    seeds: list[Seed]

    @cached_property
    def times(self) -> dict[Seed, list[Plot]]:
        return {
            seed: calculate_plots(self.directory, self.option, seed)
            for seed in rich.progress.track(
                self.seeds, description=f"Calculating Times for {self.option}"
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


def discover_seeds(directory: str, option: str) -> list[Seed]:
    return list(map(Seed, os.listdir(f"{directory}/{option}")))


def discover_options(directory: str) -> list[Options]:
    return list(map(Options, os.listdir(directory)))


@click.command()
@click.option("--directory", "-d", help="Path to the directory", required=True)
@click.option(
    "--option",
    "-o",
    "options",
    multiple=True,
    help="Options to plot, if not set will discover",
    default=[],
)
@click.option(
    "--seed",
    "-s",
    "seeds",
    multiple=True,
    help="Seed to plot, if not set will discover",
    default=[],
)
@click.option(
    "--only-average", "-a", is_flag=True, help="Only plot the average", default=False
)
@click.option("--output", "-o", help="Output file name")
def graph(
    directory: str,
    options: list[Options],
    seeds: list[Seed],
    only_average: bool,
    output: Optional[str],
) -> None:
    if not options:
        options = discover_options(directory)

    if not seeds:
        seeds = discover_seeds(directory, options[0])

    completion_times = [
        FlowCompletionTimes(directory, option, seeds) for option in options
    ]

    if only_average:
        results = {
            str(flow_completion_time.option): flow_completion_time.average
            for flow_completion_time in completion_times
        }
        standard_deviation = {
            str(flow_completion_time.option): flow_completion_time.standard_deviation
            for flow_completion_time in completion_times
        }
        plot_flow_completion_time(
            results, target=output, standard_deviation=standard_deviation
        )


if __name__ == "__main__":
    graph()
