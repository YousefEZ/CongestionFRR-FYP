from typing import Optional
import click

from analysis import discovery, graph, scenario


@click.command("graph")
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
def _graph(
    directory: str,
    options: list[scenario.Options],
    seeds: list[scenario.Seed],
    only_average: bool,
    output: Optional[str],
) -> None:
    if not options:
        options = discovery.discover_options(directory)

    if not seeds:
        seeds = discovery.discover_seeds(directory, options[0])

    completion_times = [
        scenario.Scenario(directory, option, seeds) for option in options
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
        graph.plot_flow_completion_time(
            results, target=output, standard_deviation=standard_deviation
        )


if __name__ == "__main__":
    _graph()
