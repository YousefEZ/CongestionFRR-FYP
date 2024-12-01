from typing import NamedTuple, NotRequired, Optional, TypedDict

import matplotlib.pyplot as plt

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


class Plot(NamedTuple):
    variable: float
    time: float


def _sort_plots(plots: list[Plot]) -> list[Plot]:
    return sorted(plots, key=lambda x: x.variable)


def plot(
    results: dict[str, list[Plot]],
    labels: Labels,
    target: Optional[str] = None,
    styles: Optional[dict[str, Style]] = None,
    standard_deviation: Optional[dict[str, list[Plot]]] = None,
) -> None:
    figure, axes = plt.subplots(figsize=(10, 6))

    for result_type, unsorted_plots in results.items():
        plots = _sort_plots(unsorted_plots)
        if styles:
            style = styles.get(result_type, {})
            axes.plot(
                [plot.variable for plot in plots],
                [plot.time for plot in plots],
                label=result_type,
                **style.get(result_type, {}),
            )
        else:
            axes.plot(
                [plot.variable for plot in plots],
                [plot.time for plot in plots],
                label=result_type,
            )

        if standard_deviation:
            standard_deviation_plots = _sort_plots(standard_deviation[result_type])
            axes.fill_between(
                [plot.variable for plot in standard_deviation_plots],
                [
                    plot.time - sd_plot.time
                    for plot, sd_plot in zip(plots, standard_deviation_plots)
                ],
                [
                    plot.time + sd_plot.time
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
