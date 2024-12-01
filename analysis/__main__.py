from typing import Optional
import click

from analysis import discovery, graph, scenario


@click.group(name="graph")
def _graph() -> None:
    ...


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

    results = {
        str(flow_completion_time.option): flow_completion_time.times.average
        for flow_completion_time in scenarios
    }
    standard_deviation = {
        str(flow_completion_time.option): flow_completion_time.times.standard_deviation
        for flow_completion_time in scenarios
    }
    graph.plot(results, target=output, standard_deviation=standard_deviation)


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

    results = {
        str(flow_completion_time.option): flow_completion_time.packet_loss.average
        for flow_completion_time in scenarios
    }
    standard_deviation = {
        str(
            flow_completion_time.option
        ): flow_completion_time.packet_loss.standard_deviation
        for flow_completion_time in scenarios
    }
    graph.plot(results, target=output, standard_deviation=standard_deviation)


if __name__ == "__main__":
    _graph()
