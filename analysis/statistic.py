from dataclasses import dataclass
from functools import cached_property
from typing import NamedTuple

from analysis import discovery, graph


class PlotList(NamedTuple):
    variable: float
    data: list[float]


def _variance(times: list[float], average: float) -> float:
    return sum([(time - average) ** 2 for time in times]) / (len(times) - 1)


@dataclass(frozen=True)
class Statistic:
    data: dict[discovery.Seed, list[graph.Plot]]

    @cached_property
    def variables(self):
        return sorted([plot.variable for plot in list(self.data.values())[0]])

    @cached_property
    def plots(self) -> list[PlotList]:
        plot_lists = [PlotList(variable, []) for variable in self.variables]
        for times in self.data.values():
            for plot_list, seed_plot in zip(plot_lists, times):
                plot_list.data.append(seed_plot.time)
        return plot_lists

    @property
    def average(self) -> list[graph.Plot]:
        assert self.data
        return [
            graph.Plot(plot.variable, sum(plot.data) / len(plot.data))
            for plot in self.plots
        ]

    @property
    def variance(self) -> list[graph.Plot]:
        assert self.data

        return [
            graph.Plot(plot.variable, _variance(plot.data, average.time))
            for average, plot in zip(self.average, self.plots)
        ]

    @property
    def standard_deviation(self) -> list[graph.Plot]:
        assert self.data

        return [
            graph.Plot(plot.variable, variance.time**0.5)
            for variance, plot in zip(self.variance, self.plots)
        ]
