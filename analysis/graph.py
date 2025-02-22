from __future__ import annotations

from typing import (
    TYPE_CHECKING,
    NamedTuple,
    NotRequired,
    Optional,
    Sequence,
    TypedDict,
)

from matplotlib.axes import Axes
import matplotlib.pyplot as plt
import numpy as np
from numpy.typing import NDArray
from pydantic import BaseModel
import matplotlib.colors as mcolors

if TYPE_CHECKING:
    from analysis import statistic
from analysis.discovery import Options, Seed


class Style(TypedDict):
    marker: str
    color: str
    linestyle: str


class Customisation(TypedDict):
    styles: NotRequired[dict[str, Style]]


class Labels(TypedDict):
    y_axis: str
    x_axis: str
    title: str


class Plot(BaseModel):
    variable: float
    value: float

    def __sub__(self, other: Plot) -> Plot:
        assert self.variable == other.variable
        return Plot(variable=self.variable, value=self.value - other.value)

    def __hash__(self) -> int:
        return hash((self.variable, self.value))


def _sort_plots(plots: list[Plot]) -> list[Plot]:
    return sorted(plots, key=lambda x: x.variable)


def correlation_scatter(
    stats: tuple[
        dict[Options, statistic.Statistic], dict[Options, statistic.Statistic]
    ],
    labels: Labels,
    target: Optional[str] = None,
    styles: Optional[dict[str, Style]] = None,
    correlation_lines: bool = False,
) -> None:
    # show first average statistic on x-axis and second average statistic on y-axis

    figure, axes = plt.subplots(figsize=(10, 6))
    options = list(stats[0].keys())

    for option, first, second in zip(options, stats[0].values(), stats[1].values()):
        cmap = plt.get_cmap("viridis")
        norm = mcolors.Normalize(
            vmin=first.plots[0].variable, vmax=first.plots[-1].variable
        )  # Normalize for color scaling
        for independent_plot_list, dependent_plot_list in zip(
            first.plots, second.plots
        ):
            assert independent_plot_list.variable == dependent_plot_list.variable, (
                "Variables do not match"
            )
            if styles:
                style = styles.get(option, {})
                scatter = axes.scatter(
                    independent_plot_list.data,
                    dependent_plot_list.data,
                    label=independent_plot_list.variable,
                    color=cmap(norm(independent_plot_list.variable)),
                    **style.get(option, {}),
                )

            else:
                scatter = axes.scatter(
                    independent_plot_list.data,
                    dependent_plot_list.data,
                    label=independent_plot_list.variable,
                    color=cmap(norm(independent_plot_list.variable)),
                )

            if correlation_lines:
                colour = scatter.get_facecolor()[0]
                try:
                    slope, intercept = np.polyfit(
                        independent_plot_list.data, dependent_plot_list.data, 1
                    )
                    plt.plot(
                        independent_plot_list.data,
                        np.poly1d((slope, intercept))(independent_plot_list.data),
                        color=colour,
                    )
                except Exception:
                    pass
    axes.set_ylabel(labels["y_axis"])
    axes.set_xlabel(labels["x_axis"])
    axes.set_title(labels["title"])
    axes.legend()

    figure.subplots_adjust(left=0.2)

    if target:
        figure.savefig(target, dpi=300)
    else:
        figure.show()

    figure.clf()


def single_point_plot(
    stats: dict[Options, statistic.Statistic],
    axes: Axes,
    option: Options,
    styles: Optional[dict[str, Style]] = None,
) -> None:
    average_plot = stats[option].average[0]
    std_dev = stats[option].standard_deviation[0].value
    if styles:
        style = styles.get(option, {})
        axes.errorbar(
            [average_plot.variable],
            [average_plot.value],
            xerr=0,
            yerr=std_dev,
            label=option,
            **style.get(option, {}),
        )
    else:
        axes.errorbar(
            [average_plot.variable],
            [average_plot.value],
            xerr=0,
            yerr=std_dev,
            label=option,
        )


def min_max_plot(
    stats: dict[Options, statistic.Statistic],
    labels: Labels,
    target: Optional[str] = None,
    styles: Optional[dict[str, Style]] = None,
) -> None:
    figure, axes = plt.subplots(figsize=(10, 6))

    for option, statistic in stats.items():
        plots = _sort_plots(statistic.average)
        axes.plot(
            [plot.variable for plot in plots],
            [plot.value for plot in plots],
        )
        if styles:
            style = styles.get(option, {})
            axes.errorbar(
                [plot.variable for plot in plots],
                [plot.value for plot in plots],
                xerr=0,
                yerr=[
                    [
                        abs(a.value - s.value)
                        for a, s in zip(plots, _sort_plots(statistic.minimum))
                    ],
                    [
                        abs(a.value - s.value)
                        for a, s in zip(plots, _sort_plots(statistic.maximum))
                    ],
                ],
                label=option,
                fmt="o",
                **style.get(option, {}),
            )
        else:
            axes.errorbar(
                [plot.variable for plot in plots],
                [plot.value for plot in plots],
                xerr=0,
                yerr=[
                    [
                        abs(a.value - s.value)
                        for a, s in zip(plots, _sort_plots(statistic.minimum))
                    ],
                    [
                        abs(a.value - s.value)
                        for a, s in zip(plots, _sort_plots(statistic.maximum))
                    ],
                ],
                label=option,
                fmt="o",
            )
    axes.set_ylabel(labels["y_axis"])
    axes.set_xlabel(labels["x_axis"])
    axes.set_title(labels["title"])
    axes.legend()

    figure.subplots_adjust(left=0.2)

    if target:
        figure.savefig(target, dpi=300)
    else:
        figure.show()

    figure.clf()


def plot(
    stats: dict[Options, statistic.Statistic],
    labels: Labels,
    target: Optional[str] = None,
    styles: Optional[dict[str, Style]] = None,
) -> None:
    figure, axes = plt.subplots(figsize=(10, 6))

    for option, statistic in stats.items():
        plots = _sort_plots(statistic.average)
        if len(plots) == 1:
            single_point_plot(stats, axes, option, styles)
            continue
        if styles:
            style = styles.get(option, {})
            axes.plot(
                [plot.variable for plot in plots],
                [plot.value for plot in plots],
                label=option,
                **style.get(option, {}),
            )
        else:
            axes.plot(
                [plot.variable for plot in plots],
                [plot.value for plot in plots],
                label=option,
            )

        standard_deviation_plots = _sort_plots(statistic.standard_deviation)
        axes.fill_between(
            [plot.variable for plot in standard_deviation_plots],
            [
                plot.value - sd_plot.value
                for plot, sd_plot in zip(plots, standard_deviation_plots)
            ],
            [
                plot.value + sd_plot.value
                for plot, sd_plot in zip(plots, standard_deviation_plots)
            ],
            alpha=0.2,
        )

    axes.set_ylabel(labels["y_axis"])
    axes.set_xlabel(labels["x_axis"])
    axes.set_title(labels["title"])
    axes.legend()

    figure.subplots_adjust(left=0.2)

    if target:
        figure.savefig(target, dpi=300)
    else:
        figure.show()

    figure.clf()


class SeededPlots(NamedTuple):
    baseline: list[Plot]
    alternative: list[Plot]


def cdf(
    plots: Sequence[np.number] | NDArray[np.number],
    labels: Labels,
    target: Optional[str] = None,
    styles: Optional[dict[str, Style]] = None,
):
    figure, axes = plt.subplots(figsize=(10, 6))

    axes.hist(
        plots,
        bins=100,
        density=True,
        histtype="step",
        cumulative=True,
        label="CDF",
    )

    axes.set_ylabel(labels["y_axis"])
    axes.set_xlabel(labels["x_axis"])
    axes.set_title(labels["title"])
    axes.legend()

    figure.subplots_adjust(left=0.2)

    if target:
        figure.savefig(target, dpi=300)
    else:
        figure.show()

    figure.clf()


def cdf_time_diff(
    baseline: dict[Seed, list[Plot]],
    alternative: dict[Seed, list[Plot]],
    labels: Labels,
    target: Optional[str] = None,
    styles: Optional[dict[str, Style]] = None,
) -> None:
    def _take_value(plots: list[Plot]) -> list[float]:
        return [plot.value for plot in plots]

    differences: NDArray[np.float64] = np.concatenate(
        [
            np.array(_take_value(_sort_plots(baseline[seed])))
            - np.array(_take_value(_sort_plots(alternative[seed])))
            for seed in baseline.keys()
        ]
    )
    cdf(differences, labels, target, styles)
