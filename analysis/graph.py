from typing import NamedTuple, NotRequired, Optional, TypedDict
import matplotlib.pyplot as plt

__all__ = "Customisation", "Plot", "plot_flow_completion_time"


class Style(TypedDict):
    marker: str
    color: str
    linestyle: str


class Customisation(TypedDict):
    mode: NotRequired[str]
    markers: NotRequired[dict[str, Style]]
    title: NotRequired[str]


class Plot(NamedTuple):
    variable: float
    time: float


def _sort_plots(plots: list[Plot]) -> list[Plot]:
    return sorted(plots, key=lambda x: x.variable)


def plot_flow_completion_time(
    results: dict[str, list[Plot]],
    target: Optional[str] = None,
    labels: Customisation = Customisation(),
) -> None:
    figure, axes = plt.subplots(figsize=(10, 6))

    for result_type, unsorted_plots in results.items():
        plots = _sort_plots(unsorted_plots)
        style = labels.get("markers", {}).get(result_type, {})
        axes.plot(
            [plot.variable for plot in plots],
            [plot.time for plot in plots],
            label=result_type,
            **style,
        )

    axes.set_ylabel("Flow Complete Time in Seconds")
    axes.set_xlabel(labels.get("mode", ""))
    axes.set_title(labels.get("title", ""))
    axes.legend()

    figure.legend(
        results.keys(),
        loc="upper left",
        fontsize="large",
        title="Legend",
    )
    figure.subplots_adjust(left=0.2)

    if target:
        figure.savefig(target, dpi=300)
    else:
        figure.show()

    figure.clf()
