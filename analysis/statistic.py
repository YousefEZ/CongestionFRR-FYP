from dataclasses import dataclass
from functools import cached_property
from typing import NamedTuple


from analysis import discovery, graph


class PlotList(NamedTuple):
    variable: float
    data: list[float]


def _variance(values: list[float], average: float) -> float:
    return sum([(value - average) ** 2 for value in values]) / (len(values) - 1)


@dataclass(frozen=True)
class Statistic:
    data: dict[discovery.Seed, list[graph.Plot]]

    @cached_property
    def variables(self):
        return sorted([plot.variable for plot in list(self.data.values())[0]])

    @cached_property
    def plots(self) -> list[PlotList]:
        plot_lists = [PlotList(variable, []) for variable in self.variables]
        for value in self.data.values():
            for plot_list, seed_plot in zip(plot_lists, value):
                plot_list.data.append(seed_plot.value)
        return plot_lists

    @property
    def average(self) -> list[graph.Plot]:
        assert self.data
        return [
            graph.Plot(variable=plot.variable, value=sum(plot.data) / len(plot.data))
            for plot in self.plots
        ]

    @property
    def variance(self) -> list[graph.Plot]:
        assert self.data

        return [
            graph.Plot(
                variable=plot.variable, value=_variance(plot.data, average.value)
            )
            for average, plot in zip(self.average, self.plots)
        ]

    @property
    def standard_deviation(self) -> list[graph.Plot]:
        assert self.data

        return [
            graph.Plot(variable=plot.variable, value=variance.value**0.5)
            for variance, plot in zip(self.variance, self.plots)
        ]
