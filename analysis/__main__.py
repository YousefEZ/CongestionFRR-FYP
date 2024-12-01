import operator
from typing import Callable, NamedTuple, Optional

import click

from analysis import discovery, graph, scenario, statistic


@click.group(name="analysis")
def _analysis() -> None: ...


@click.group(name="graph")
def _graph() -> None: ...


def generate_scenarios(
    directory: str,
    options: Optional[list[discovery.Options]],
    seeds: list[discovery.Seed],
) -> list[scenario.Scenario]:
    if not options:
        options = discovery.discover_options(directory)
    if not seeds:
        seeds = discovery.discover_seeds(directory, options[0])
    return [scenario.Scenario(directory, option, seeds) for option in options]


class OptionStatistics(NamedTuple):
    average: dict[str, list[graph.Plot]]
    standard_deviation: dict[str, list[graph.Plot]]


def get_option_statistics(
    scenarios: list[scenario.Scenario],
    statistic: Callable[[scenario.Scenario], statistic.Statistic],
) -> OptionStatistics:
    average = {
        str(scenario.option): statistic(scenario).average for scenario in scenarios
    }
    standard_deviation = {
        str(scenario.option): statistic(scenario).standard_deviation
        for scenario in scenarios
    }
    return OptionStatistics(average, standard_deviation)


@_graph.command(name="time")
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
@click.option("--output", "-o", help="Output file name")
def _time(
    directory: str,
    options: list[discovery.Options],
    seeds: list[discovery.Seed],
    output: Optional[str],
) -> None:
    scenarios = generate_scenarios(directory, options, seeds)

    statistic_getter = operator.attrgetter("packet_loss")
    completion_time = get_option_statistics(scenarios, statistic_getter)

    graph.plot(
        completion_time.average,
        graph.Labels(
            x_axis=directory,
            y_axis="Flow Completion Time (s)",
            title=f"Flow Completion time for {directory}",
        ),
        target=output,
        standard_deviation=completion_time.standard_deviation,
    )


@_graph.command("loss")
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
@click.option("--output", "-o", help="Output file name")
def _loss(
    directory: str,
    options: list[discovery.Options],
    seeds: list[discovery.Seed],
    output: Optional[str],
) -> None:
    scenarios = generate_scenarios(directory, options, seeds)
    statistic_getter = operator.attrgetter("packet_loss")
    packet_loss = get_option_statistics(scenarios, statistic_getter)

    graph.plot(
        packet_loss.average,
        graph.Labels(
            x_axis=directory,
            y_axis="Packet Loss (%)",
            title=f"Packet Loss % for {directory}",
        ),
        target=output,
        standard_deviation=packet_loss.standard_deviation,
    )


_analysis.add_command(_graph)

if __name__ == "__main__":
    _analysis()
