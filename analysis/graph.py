from __future__ import annotations

from typing import NamedTuple, NotRequired, Optional, TypedDict

import matplotlib.pyplot as plt
import numpy as np
from pydantic import BaseModel

from analysis.discovery import Options, Seed

__all__ = "Customisation", "Plot", "plot"


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


def plot(
    results: dict[Options, list[Plot]],
    labels: Labels,
    target: Optional[str] = None,
    styles: Optional[dict[str, Style]] = None,
    standard_deviation: Optional[dict[Options, list[Plot]]] = None,
) -> None:
    figure, axes = plt.subplots(figsize=(10, 6))

    for result_type, unsorted_plots in results.items():
        plots = _sort_plots(unsorted_plots)
        if styles:
            style = styles.get(result_type, {})
            axes.plot(
                [plot.variable for plot in plots],
                [plot.value for plot in plots],
                label=result_type,
                **style.get(result_type, {}),
            )
        else:
            axes.plot(
                [plot.variable for plot in plots],
                [plot.value for plot in plots],
                label=result_type,
            )

        if standard_deviation:
            standard_deviation_plots = _sort_plots(standard_deviation[result_type])
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
    baseline: dict[Seed, list[Plot]],
    alternative: dict[Seed, list[Plot]],
    labels: Labels,
    target: Optional[str] = None,
    styles: Optional[dict[str, Style]] = None,
) -> None:
    figure, axes = plt.subplots(figsize=(10, 6))

    def _take_value(plots: list[Plot]) -> list[float]:
        return [plot.value for plot in plots]

    differences = np.concatenate(
        [
            np.array(_take_value(_sort_plots(baseline[seed])))
            - np.array(_take_value(_sort_plots(alternative[seed])))
            for seed in baseline.keys()
        ]
    )

    axes.hist(
        differences,
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

    figure.clf
