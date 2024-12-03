from dataclasses import dataclass
from typing import Callable, Literal, Optional, ParamSpec, TypeVar

import click

from analysis import discovery, graph, scenario

P = ParamSpec("P")
T = TypeVar("T")

GraphTypes = Literal["plot", "cdf"]
graph_types: list[GraphTypes] = ["plot", "cdf"]


def multi_command(
    *groups: click.Group, name: str
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    def decorator(command: Callable[P, T]) -> Callable[P, T]:
        for group in groups:

            @group.command(name=name)
            def _(*args: P.args, **kwargs: P.kwargs) -> T:
                return command(*args, **kwargs)

        return command

    return decorator


def generate_scenarios(
    directory: str,
    options: Optional[list[discovery.Options]],
    seeds: list[discovery.Seed],
) -> dict[discovery.Options, scenario.Scenario]:
    if not options:
        options = discovery.discover_options(directory)
    if not seeds:
        seeds = discovery.discover_seeds(directory, options[0])
    return {option: scenario.Scenario(directory, option, seeds) for option in options}


@dataclass(frozen=True)
class GraphArguments:
    directory: str
    options: list[discovery.Options]
    seeds: list[discovery.Seed]
    output: Optional[str]


@click.group(name="analysis")
def _analysis() -> None: ...


@click.group(name="graph")
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
@click.pass_context
def _graph(
    ctx: click.Context,
    directory: str,
    options: list[discovery.Options],
    seeds: list[discovery.Seed],
    output: Optional[str],
) -> None:
    ctx.ensure_object(dict)
    ctx.obj["arguments"] = GraphArguments(
        directory=directory, options=options, seeds=seeds, output=output
    )

    ctx.obj["scenarios"] = generate_scenarios(directory, options, seeds)


@click.group(name="time")
@click.pass_context
def _time(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.times for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Flow Completion Time (s)"
    ctx.obj["title"] = "Flow Completion time"


@click.group(name="loss")
@click.pass_context
def _loss(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.packet_loss
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Packet Loss (%)"
    ctx.obj["title"] = "Packet Loss"


@click.group(name="reordering")
@click.pass_context
def _reordering(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.reordering for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Packet Reordering Amount"
    ctx.obj["title"] = "Packet Reordering"


@multi_command(_time, _loss, _reordering, name="cdf")
@click.pass_context
def cdf(ctx: click.Context) -> None:
    arguments = ctx.obj["arguments"]
    stats = ctx.obj["statistics"]
    graph.cdf(
        stats["baseline-udp"].data,
        stats["frr"].data,
        graph.Labels(
            x_axis=arguments.directory,
            y_axis="Probability of Occurrence",
            title=ctx.obj["title"],
        ),
        target=arguments.output,
    )


@multi_command(_time, _loss, _reordering, name="plot")
@click.pass_context
def plot(ctx: click.Context) -> None:
    arguments = ctx.obj["arguments"]
    stats = ctx.obj["statistics"]

    graph.plot(
        stats,
        graph.Labels(
            x_axis=arguments.directory,
            y_axis=ctx.obj["property"],
            title=ctx.obj["title"],
        ),
        target=arguments.output,
    )


_graph.add_command(_loss)
_graph.add_command(_time)
_graph.add_command(_reordering)
_analysis.add_command(_graph)

if __name__ == "__main__":
    _analysis()
