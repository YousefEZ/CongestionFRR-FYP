from dataclasses import dataclass
import operator
from typing import Callable, Literal, Optional, ParamSpec, TypeVar

import click
import rich
import rich.table

from analysis import discovery, graph, scenario
from analysis.generator import Configuration, run_experiments
from analysis.sequence_plot import (
    Packets,
    build_conditions,
    plot_bytesInFlight,
    plot_sequence,
)
from analysis.trace_analyzer.dst.reordered_packets import (
    OOOAnalyzer,
    PacketOutOfOrderAnalyzer,
    SpuriousOOOAnalyzer,
    TrueBytesInFlightAnalyzer,
    congestion_windows,
    hashable_packet,
    tcp_bytes_in_flight,
)
from analysis.trace_analyzer.dst.spurious_retransmission_packets import (
    SpuriousRetransmissionAnalyzer,
)
from analysis.trace_analyzer.source.dropped_packets import DroppedPacketsAnalyzer
from analysis.trace_analyzer.source.regular_fast_retransmit import (
    FastRetransmissionAnalyzer,
)
from analysis.trace_analyzer.source.replayer import TcpSourceReplayer
from analysis.trace_analyzer.source.sack_fast_retransmit import (
    FastRetransmitSackAnalyzer,
)
from analysis.trace_analyzer.source.spurious_sack_fast_transmit import (
    SingleDupAckRetransmitSackAnalyzer,
)

P = ParamSpec("P")
T = TypeVar("T")

GraphTypes = Literal["plot", "cdf"]
graph_types: list[GraphTypes] = ["plot", "cdf"]


@click.group(name="analysis")
def _analysis() -> None: ...


@click.command("simulate")
@click.option(
    "--config",
    "-c",
    "config_filename",
    help="Path to the configuration",
    type=str,
    required=True,
)
def _simulate(config_filename: str) -> None:
    with open(config_filename, "r") as file:
        configuration = Configuration.model_validate_json(file.read())
        run_experiments(configuration)


def multi_command(
    *groups: click.Group, name: str
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        if hasattr(func, "__click_params__"):
            # need to preserve it as command deletes it
            params = func.__click_params__  # type: ignore
        else:
            params = None
        for group in groups:
            new_func = group.command(name=name)(func)
            if params is not None:
                new_func.params = params
        return func

    return decorator


def generate_scenarios(
    *,
    directory: str,
    options: Optional[list[discovery.Options]],
    seeds: list[discovery.Seed],
    variables: list[discovery.Variable],
) -> dict[discovery.Options, scenario.Scenario]:
    if not options:
        options = discovery.discover_options(directory)
    if not seeds:
        seeds = discovery.discover_seeds(directory, options[0])
    if not variables:
        variables = discovery.discover_variables(directory, options[0], seeds[0])
    return {
        option: scenario.Scenario(
            directory=directory, option=option, seeds=seeds, variables=tuple(variables)
        )
        for option in options
    }


@dataclass(frozen=True)
class GraphArguments:
    directory: str
    options: list[discovery.Options]
    seeds: list[discovery.Seed]
    variables: list[discovery.Variable]
    output: Optional[str]


@click.command("bytesInFlight")
@click.option("--directory", "-d", help="Path to the directory", required=True)
@click.option("--directory", "-d", help="Path to the directory", required=True)
@click.option("--option", "-o", help="Option of the run", required=True)
@click.option("--seed", "-s", help="Seed of the run", required=True)
@click.option("--value", "-v", help="Value to display e.g. 3.0Mbps", required=True)
@click.option("--sender", "-s", help="Traffic Sender number", default=1, type=int)
def _bytesInFlight(
    directory: str,
    option: discovery.Options,
    seed: discovery.Seed,
    value: discovery.Variable,
    sender: int,
) -> None:
    run = scenario.VariableRun(directory, option, seed, (value,))
    traffic_sender, receiver = run.senders[value][sender], run.receivers[value]
    source, dst = run.ip_addresses(value)

    dropped_packets = DroppedPacketsAnalyzer(traffic_sender, receiver).filter_packets(
        source, dst
    )
    capture = TrueBytesInFlightAnalyzer(
        lost_packets=[hashable_packet(pkt) for pkt in dropped_packets]
    )
    TcpSourceReplayer(
        file=traffic_sender, source=source, destination=dst, event_handlers=capture
    ).run()

    plot_bytesInFlight(
        capture.bytes_in_flight,
        tcp_bytes_in_flight(run.debug_filename(value), sender),
        congestion_windows(run.cwnd_filename(value, sender)),
    )


@click.command("sequence")
@click.option("--directory", "-d", help="Path to the directory", required=True)
@click.option("--option", "-o", help="Option of the run", required=True)
@click.option("--seed", "-s", help="Seed of the run", required=True)
@click.option("--value", "-v", help="Value to display e.g. 3.0Mbps", required=True)
@click.option("--sender-seq", help="Sender ack", is_flag=True, default=False)
@click.option("--sender-ack", help="Sender ack", is_flag=True, default=False)
@click.option(
    "--receiver-seq",
    help="Receiver receiving a sequence number",
    is_flag=True,
    default=False,
)
@click.option(
    "--receiver-ack", help="Receiver sending an ack", is_flag=True, default=False
)
@click.option("--sender", "-s", help="Traffic Sender number", default=1, type=int)
def _sequence(
    directory: str,
    option: discovery.Options,
    seed: discovery.Seed,
    value: discovery.Variable,
    sender_seq: bool,
    sender_ack: bool,
    receiver_seq: bool,
    receiver_ack: bool,
    sender: int,
) -> None:
    run = scenario.VariableRun(directory, option, seed, (value,))
    traffic_sender, receiver = run.senders[value][sender], run.receivers[value]
    source, dst = run.flow_ip_addresses(value)[sender]

    packet_lists = []
    if sender_seq:
        packet_lists.append(
            Packets(
                "Sender Seq",
                traffic_sender.packets_from(source),
                operator.attrgetter("seq"),
                build_conditions(
                    SpuriousOOOAnalyzer(traffic_sender, receiver),
                    SingleDupAckRetransmitSackAnalyzer(traffic_sender, receiver),
                    FastRetransmitSackAnalyzer(traffic_sender),
                    FastRetransmissionAnalyzer(traffic_sender),
                    DroppedPacketsAnalyzer(traffic_sender, receiver),
                    OOOAnalyzer(traffic_sender, receiver),
                    source=source,
                    destination=dst,
                ),
            )
        )
    if sender_ack:
        packet_lists.append(
            Packets(
                "Sender Ack",
                traffic_sender.packets_from(dst),
                operator.attrgetter("ack"),
            )
        )
    if receiver_seq:
        print(receiver.filename)
        packet_lists.append(
            Packets(
                "Receiver Seq",
                receiver.packets_from(source),
                operator.attrgetter("seq"),
                build_conditions(
                    SpuriousRetransmissionAnalyzer(receiver),
                    PacketOutOfOrderAnalyzer(receiver),
                    source=source,
                    destination=dst,
                ),
            )
        )

    if receiver_ack:
        packet_lists.append(
            Packets(
                "Receiver Ack",
                traffic_sender.packets_from(dst),
                operator.attrgetter("ack"),
            )
        )

    plot_sequence(*packet_lists)


@click.group(name="graph")
@click.option("--directory", "-d", help="Path to the directory", required=True)
@click.option(
    "--option",
    "-op",
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
    "--variable",
    "-v",
    "variables",
    multiple=True,
    help="variables to plot, if not set will discover",
    default=[],
)
@click.option("--output", "-o", help="Output file name")
@click.pass_context
def _graph(
    ctx: click.Context,
    directory: str,
    options: list[discovery.Options],
    variables: list[discovery.Variable],
    seeds: list[discovery.Seed],
    output: Optional[str],
) -> None:
    ctx.ensure_object(dict)
    ctx.obj["arguments"] = GraphArguments(
        directory=directory,
        options=options,
        seeds=seeds,
        variables=variables,
        output=output,
    )

    ctx.obj["scenarios"] = generate_scenarios(
        directory=directory, options=options, seeds=seeds, variables=variables
    )


@click.group(name="udp_loss")
@click.pass_context
def _udp_loss(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.udp_loss for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Packet Loss (%)"
    ctx.obj["title"] = "Packet Loss"


@click.group(name="udp_lost")
@click.pass_context
def _udp_lost(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.udp_lost for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Lost Packets"
    ctx.obj["title"] = "Lost Packets"


@click.group(name="time")
@click.pass_context
def _time(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.times for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Flow Completion Time (s)"
    ctx.obj["title"] = "Flow Completion time"


@click.group(name="total_recovery_time")
@click.pass_context
def _total_recovery_time(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.total_recovery_time
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Total Recovery Time (s)"
    ctx.obj["title"] = "Total Recovery Time"


@click.group(name="loss")
@click.pass_context
def _loss(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.packet_loss
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Packet Loss (%)"
    ctx.obj["title"] = "Packet Loss"


@click.group(name="lost")
@click.pass_context
def _lost(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.packets_lost
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Lost Packets"
    ctx.obj["title"] = "Lost Packets"


@click.group(name="reordering")
@click.pass_context
def _reordering(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.reordering for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Packet Reordering Amount"
    ctx.obj["title"] = "Packet Reordering"


@click.group(name="rerouted")
@click.pass_context
def _rerouted(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.rerouted for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Rerouted Packets"
    ctx.obj["title"] = "Rerouted Packets"


@click.group(name="rerouted_percentage")
@click.pass_context
def _rerouted_percentage(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.rerouted_percentage
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Rerouted Packets Percentage"
    ctx.obj["title"] = "Rerouted Packets Percentage"


@click.group(name="udp_rerouted")
@click.pass_context
def _udp_rerouted(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.udp_rerouted
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Rerouted Packets"
    ctx.obj["title"] = "Rerouted Packets"


@click.group(name="udp_rerouted_percentage")
@click.pass_context
def _udp_rerouted_percentage(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.udp_rerouted_percentage
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Rerouted Packets Percentage"
    ctx.obj["title"] = "Rerouted Packets Percentage"


@click.group(name="spurious_retransmissions")
@click.pass_context
def _spurious_retransmissions(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.spurious_retransmissions
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Spurious Retransmissions"
    ctx.obj["title"] = "Spurious Retransmissions"


@click.group(name="spurious_retransmissions_from_reordering")
@click.pass_context
def _spurious_retransmissions_reordering(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.spurious_retransmissions_from_reordering
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Spurious Retransmissions From Reordering"
    ctx.obj["title"] = "Spurious Retransmissions From Reordering"


@click.group(name="longest_number_spurious_retransmissions_before_rto")
@click.pass_context
def _longest_number_spurious_retransmissions_before_rto(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.longest_number_of_packets_spuriously_retransmitted_before_rto
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Longest Number of Spurious Retransmissions Before RTO"
    ctx.obj["title"] = "Longest Number of Spurious Retransmissions Before RTO"


@click.group(name="rto_wait_time")
@click.pass_context
def _rto_wait_time(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.rto_wait_time
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "RTO wait time"
    ctx.obj["title"] = "RTO wait time"


@click.group(name="dropped_retransmitted_packets")
@click.pass_context
def _dropped_retransmitted_packets(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.dropped_retransmitted_packets
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Dropped Retransmitted Packets"
    ctx.obj["title"] = "Dropped Retransmitted Packets"


@click.group(name="rto_wait_time_unsent_data")
@click.pass_context
def _rto_wait_time_unsent_data(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.rto_wait_time_for_unsent
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "RTO wait time on unsent data"
    ctx.obj["title"] = "RTO wait time on unsent data"


@click.group(name="time_multi_flow")
@click.pass_context
def _time_multi_flow(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.times_multi_flow
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Flow Completion Time (s)"
    ctx.obj["title"] = "Flow Completion time"


@click.group(name="average_time")
@click.pass_context
def _average_time(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.average_time
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Flow Completion Time (s)"
    ctx.obj["title"] = "Flow Completion time"


@click.group(name="max_flow_time")
@click.pass_context
def _max_flow_time(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.max_flow_time
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Flow Completion Time (s)"
    ctx.obj["title"] = "Flow Completion time"


@click.group(name="average_congestion_window")
@click.pass_context
def _average_congestion_window(ctx: click.Context) -> None:
    ctx.obj["statistics"] = {
        option: scenario.average_congestion_window
        for option, scenario in ctx.obj["scenarios"].items()
    }
    ctx.obj["property"] = "Average Congestion Window"
    ctx.obj["title"] = "Average Congestion Window"


statistics = (
    _max_flow_time,
    _time,
    _time_multi_flow,
    _average_time,
    _total_recovery_time,
    _loss,
    _lost,
    _reordering,
    _rerouted,
    _rerouted_percentage,
    _udp_lost,
    _udp_loss,
    _udp_rerouted,
    _udp_rerouted_percentage,
    _spurious_retransmissions,
    _rto_wait_time,
    _rto_wait_time_unsent_data,
    _dropped_retransmitted_packets,
    _spurious_retransmissions_reordering,
    _longest_number_spurious_retransmissions_before_rto,
    _average_congestion_window,
)


@multi_command(*statistics, name="cdf_diff")
@click.pass_context
def cdf_diff(ctx: click.Context) -> None:
    arguments = ctx.obj["arguments"]
    stats = ctx.obj["statistics"]
    graph.cdf_time_diff(
        stats["baseline-udp"].data,
        stats["frr"].data,
        graph.Labels(
            x_axis=arguments.directory,
            y_axis="Probability of Occurrence",
            title=ctx.obj["title"],
        ),
        target=arguments.output,
    )


@multi_command(*statistics, name="cdf")
@click.option("--variable", "-v", help="Variable to plot", type=str, required=True)
@click.pass_context
def cdf(ctx: click.Context, variable: str) -> None:
    arguments = ctx.obj["arguments"]
    stats = ctx.obj["statistics"]

    first_stat = next(iter(stats.values()))

    extracted_variable = scenario.extract_numerical_value_from_string(variable)
    variable_idx = 0
    for idx in range(len(first_stat.variables)):
        if first_stat.variables[idx] == extracted_variable:
            variable_idx = idx
            break

    values = [plot[variable_idx].value for plot in first_stat.data.values()]

    graph.cdf(
        values,
        graph.Labels(
            x_axis=ctx.obj["property"],
            y_axis="Probability of Occurrence",
            title=ctx.obj["title"],
        ),
        target=arguments.output,
    )


@multi_command(*statistics, name="cdf_multi_flow")
@click.option("--variable", "-v", help="Variable to plot", type=str, required=True)
@click.pass_context
def cdf_multi_flow(ctx: click.Context, variable: str) -> None:
    arguments = ctx.obj["arguments"]
    stats = ctx.obj["statistics"]

    first_stat = next(iter(stats.values()))

    extracted_variable = scenario.extract_numerical_value_from_string(variable)
    variable_idx = 0
    for idx in range(len(first_stat.variables)):
        if first_stat.variables[idx] == extracted_variable:
            variable_idx = idx
            break

    values = {
        option: [plot[variable_idx].value for plot in stat.data.values()]
        for option, stat in stats.items()
    }

    graph.cdf_multi_flow(
        values,
        graph.Labels(
            x_axis=ctx.obj["property"],
            y_axis="Probability of Occurrence",
            title=ctx.obj["title"],
        ),
        target=arguments.output,
    )


@multi_command(*statistics, name="min_max_plot")
@click.pass_context
def min_max_plot(ctx: click.Context) -> None:
    arguments = ctx.obj["arguments"]
    stats = ctx.obj["statistics"]

    graph.min_max_plot(
        stats,
        graph.Labels(
            x_axis=arguments.directory,
            y_axis=ctx.obj["property"],
            title=ctx.obj["title"],
        ),
        target=arguments.output,
        styles={
            "no_frr_congested": {"ecolor": "blue", "color": "blue"},
            "frr": {"ecolor": "orange", "color": "orange"},
        },
    )


@multi_command(*statistics, name="plot")
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


@multi_command(*statistics, name="summary")
@click.pass_context
def summary(ctx: click.Context) -> None:
    stats = ctx.obj["statistics"]
    console = rich.console.Console()

    for option, scenario in stats.items():
        table = rich.table.Table(
            title=option,
            show_header=True,
            header_style="bold",
        )
        table.add_column("Variable")
        table.add_column("Average")
        table.add_column("Minimum")
        table.add_column("Maximum")
        table.add_column("Standard Deviation")

        averages = scenario.average
        minimums = scenario.minimum
        maximums = scenario.maximum
        standard_deviations = scenario.standard_deviation

        for variable, average, minimum, maximum, std_dev in zip(
            tuple(avg.variable for avg in averages),
            averages,
            minimums,
            maximums,
            standard_deviations,
        ):
            table.add_row(
                str(variable),
                str(round(average.value, 2)),
                str(round(minimum.value, 2)),
                str(round(maximum.value, 2)),
                str(round(std_dev.value, 2)),
            )
        console.print(table)


@multi_command(*statistics, name="table")
@click.pass_context
def table(ctx: click.Context) -> None:
    stats = ctx.obj["statistics"]
    console = rich.console.Console()

    first_stat = next(iter(stats.values()))

    for idx in range(len(first_stat.variables)):
        for option, stat in stats.items():
            table = rich.table.Table(
                title=f"{first_stat.variables[idx]} @ {option}",
                show_header=True,
                header_style="bold",
            )
            table.add_column("Seed")
            table.add_column("Value")
            for seed, value in sorted(
                list(zip(stat.seeds, stat.plots[idx].data)),
                key=lambda x: int(x[0]),
            ):
                table.add_row(
                    seed,
                    str(value),
                )
            console.print(table)


@click.group(name="against")
@click.pass_context
def _against(ctx: click.Context) -> None:
    ctx.obj["against_statistics"] = ctx.obj["statistics"]
    ctx.obj["against_property"] = ctx.obj["property"]
    ctx.obj["against_title"] = ctx.obj["title"]


@multi_command(*statistics, name="scatter")
@click.option("--line", "-l", is_flag=True, default=False)
@click.pass_context
def scatter(ctx: click.Context, line: bool) -> None:
    arguments = ctx.obj["arguments"]
    stats = (ctx.obj["statistics"], ctx.obj["against_statistics"])

    graph.correlation_scatter(
        stats,
        graph.Labels(
            x_axis=ctx.obj["property"],
            y_axis=ctx.obj["against_property"],
            title=f"{ctx.obj['title']} against {ctx.obj['against_title']}",
        ),
        target=arguments.output,
        correlation_lines=line,
    )


for statistic in statistics:
    _graph.add_command(statistic)
    _against.add_command(statistic)
    statistic.add_command(_against)

_analysis.add_command(_graph)
_analysis.add_command(_sequence)
_analysis.add_command(_bytesInFlight)
_analysis.add_command(_simulate)

if __name__ == "__main__":
    _analysis()
