from dataclasses import dataclass
from functools import cached_property
from typing import NamedTuple


from analysis import discovery, graph


class PlotList(NamedTuple):
    variable: float
    data: list[float]


class MultiFlowPlotList(NamedTuple):
    variable: float
    data: list[list[float]]


def _variance(values: list[float], average: float) -> float:
    return sum([(value - average) ** 2 for value in values]) / (len(values) - 1)


@dataclass(frozen=True)
class Statistic:
    data: dict[discovery.Seed, list[graph.Plot]]

    @cached_property
    def seeds(self) -> list[discovery.Seed]:
        return sorted(list(self.data.keys()))

    @cached_property
    def variables(self):
        return sorted([plot.variable for plot in list(self.data.values())[0]])

    @cached_property
    def plots(self) -> list[PlotList]:
        plot_lists = [PlotList(variable, []) for variable in self.variables]
        for seed in self.seeds:
            for plot_list, seed_plot in zip(plot_lists, self.data[seed]):
                assert plot_list.variable == seed_plot.variable, (
                    "Variables do not match"
                )
                plot_list.data.append(seed_plot.value)
        return plot_lists

    @property
    def minimum(self) -> list[graph.Plot]:
        assert self.data
        return [
            graph.Plot(variable=plot.variable, value=min(plot.data))
            for plot in self.plots
        ]

    @property
    def maximum(self) -> list[graph.Plot]:
        assert self.data
        return [
            graph.Plot(variable=plot.variable, value=max(plot.data))
            for plot in self.plots
        ]

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
        if len(self.data) < 2:
            return [
                graph.Plot(variable=plot.variable, value=0.0) for plot in self.plots
            ]
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


def average(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


@dataclass(frozen=True)
class MultiFlowStatistic:
    data: dict[discovery.Seed, list[graph.MultiFlowPlot]]

    @cached_property
    def seeds(self) -> list[discovery.Seed]:
        return sorted(list(self.data.keys()))

    @cached_property
    def variables(self):
        return sorted([plot.variable for plot in list(self.data.values())[0]])

    @cached_property
    def plots(self) -> list[MultiFlowPlotList]:
        plot_lists = [MultiFlowPlotList(variable, []) for variable in self.variables]
        for seed in self.seeds:
            for plot_list, seed_plot in zip(plot_lists, self.data[seed]):
                assert plot_list.variable == seed_plot.variable, (
                    "Variables do not match"
                )
                plot_list.data.append(seed_plot.value)
        return plot_lists

    @property
    def minimum(self) -> list[graph.Plot]:
        assert self.data
        return [
            graph.Plot(
                variable=plot.variable,
                value=average([min(flows) for flows in plot.data]),
            )
            for plot in self.plots
        ]

    @property
    def maximum(self) -> list[graph.Plot]:
        assert self.data
        return [
            graph.Plot(
                variable=plot.variable,
                value=average([max(flows) for flows in plot.data]),
            )
            for plot in self.plots
        ]

    @property
    def average(self) -> list[graph.Plot]:
        assert self.data
        return [
            graph.Plot(
                variable=plot.variable,
                value=average([flow for flows in plot.data for flow in flows]),
            )
            for plot in self.plots
        ]

    @property
    def variance(self) -> list[graph.Plot]:
        assert self.data
        if len(self.data) < 2:
            return [
                graph.Plot(variable=plot.variable, value=0.0) for plot in self.plots
            ]
        return [
            graph.Plot(
                variable=plot.variable,
                value=_variance(
                    [average(flows) for flows in plot.data],
                    plot_average.value,
                ),
            )
            for plot_average, plot in zip(self.average, self.plots)
        ]

    @property
    def standard_deviation(self) -> list[graph.Plot]:
        assert self.data
        return [
            graph.Plot(variable=plot.variable, value=variance.value**0.5)
            for variance, plot in zip(self.variance, self.plots)
        ]
