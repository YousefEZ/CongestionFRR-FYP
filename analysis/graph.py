from typing import NamedTuple, NotRequired, Optional, TypedDict
import matplotlib.pyplot as plt

__all__ = "Customisation", "Plot", "plot"


class Style(TypedDict):
    marker: str
    color: str
    linestyle: str


class Customisation(TypedDict):
    mode: NotRequired[str]
    style: NotRequired[dict[str, Style]]
    title: NotRequired[str]


class Plot(NamedTuple):
    variable: float
    time: float


def _sort_plots(plots: list[Plot]) -> list[Plot]:
    return sorted(plots, key=lambda x: x.variable)


def plot(
    results: dict[str, list[Plot]],
    target: Optional[str] = None,
    customisation: Customisation = Customisation(),
    standard_deviation: Optional[dict[str, list[Plot]]] = None,
) -> None:
    figure, axes = plt.subplots(figsize=(10, 6))

    for result_type, unsorted_plots in results.items():
        plots = _sort_plots(unsorted_plots)
        style: Optional[Style] = customisation.get("style", {}).get(result_type)
        if style:
            axes.plot(
                [plot.variable for plot in plots],
                [plot.time for plot in plots],
                label=result_type,
                **style,
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

    axes.set_ylabel("Flow Complete Time in Seconds")
    axes.set_xlabel(customisation.get("mode", ""))
    axes.set_title(customisation.get("title", ""))
    axes.legend()

    figure.subplots_adjust(left=0.2)

    if target:
        figure.savefig(target, dpi=300)
    else:
        figure.show()

    figure.clf()
