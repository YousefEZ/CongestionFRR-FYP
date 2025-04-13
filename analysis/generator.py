from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any, Generator, Iterable, Optional
from itertools import chain, product
import shutil
from functools import reduce
import operator

from mpire.pool import WorkerPool
from pydantic import BaseModel, ConfigDict, Field


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bandwidth_primary: str
    bandwidth_alternate: str
    bandwidth_udp: str
    bandwidth_tcp: str
    bandwidth_destination: str
    fast_rerouting_scheme: str

    delay_primary: str
    delay_alternate: str
    delay_udp: str
    delay_tcp: str
    delay_destination: str

    tcp_senders: int
    tcp_bytes: int
    tcp_segment_size: int
    tcp_start_time: float
    tcp_end_time: float
    tcp_type: str
    tcp_recovery: str

    udp_start_time: float
    udp_segment_size: int
    udp_end_time: float

    udp_on_time_mean: float
    udp_on_time_variance: float
    udp_on_time_bound: float

    udp_off_time_mean: float
    udp_off_time_variance: float
    udp_off_time_bound: float

    traffic_queue_size: str
    default_queue_size: str

    policy_threshold: int

    def options(self, exclude: Iterable[str]) -> dict[str, str]:
        return {
            key: value for key, value in self.model_dump().items() if key not in exclude
        }


class OverwrittenSetting(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_settings: str

    for key in Settings.__annotations__:
        locals()[key] = None
        del key

    __annotations__.update(
        {key: Optional[value] for key, value in Settings.__annotations__.items()}
    )

    def fetch_settings(self) -> Settings:
        with open(self.base_settings) as file:
            return Settings.model_validate_json(file.read())

    def apply(self) -> Settings:
        settings = self.fetch_settings()
        overwritten_settings = self.model_dump()
        return Settings(
            **{
                key: (
                    overwritten_settings[key]
                    if overwritten_settings[key] is not None
                    else getattr(settings, key)
                )
                for key in settings.model_dump().keys()
            }
        )


@dataclass(frozen=True)
class Command:
    conditions: Conditions
    main_directory: str
    variables: dict[str, Any]
    seed: int
    run: int
    condition_label: str
    variable_label: str
    settings: Settings

    @property
    def directory(self) -> str:
        return os.path.join(
            self.main_directory,
            self.variable_label,
            self.condition_label,
            f"{self.seed}{self.run}",
            "_".join((str(value) for value in self.variables.values())),
        )

    def generate_dir(self) -> None:
        if os.path.exists(self.directory):
            shutil.rmtree(self.directory)
        os.makedirs(self.directory)

    def options(self) -> list[str]:
        command_options = []
        for key, value in chain(
            self.settings.options(self.variables).items(), self.variables.items()
        ):
            command_options.append(f"--{key}={value}")

        command_options.append(f"--dir={self.directory}/")
        command_options.append(f"--seed={self.seed}")
        command_options.append(f"--run={self.run}")

        if self.conditions.fast_rerouting:
            command_options.append("--enable-rerouting")
        if self.conditions.congestion:
            command_options.append("--enable-udp")

        if self.conditions.enable_router_pcap:
            command_options.append("--enable-router-pcap")
        if self.conditions.enable_udp_pcap:
            command_options.append("--enable-udp-pcap")
        if self.conditions.enable_logging:
            command_options.append("--enable-logging")
        return command_options

    def generate(self) -> str:
        return 'NS_LOG="" ./ns3 run "scratch/simulation.cc {}" 2> {}/debug.log > /dev/null'.format(
            " ".join(self.options()), self.directory
        )

    def execute(self) -> None:
        self.generate_dir()
        os.system(self.generate())


class Conditions(BaseModel):
    fast_rerouting: bool
    congestion: bool
    enable_router_pcap: bool = Field(default=False)
    enable_udp_pcap: bool = Field(default=False)
    enable_logging: bool = Field(default=False)


class Variable(BaseModel):
    name: str
    values: list[Any]


class Configuration(BaseModel):
    overwrite_settings: OverwrittenSetting
    variables: list[Variable]
    directory: str
    conditions: dict[str, Conditions]
    seed: int
    number_of_runs: int

    def _no_variable_runs(self) -> Generator[Command, None, None]:
        for option, conditions in self.conditions.items():
            for run in range(self.number_of_runs):
                yield Command(
                    conditions=conditions,
                    main_directory=self.directory,
                    variables={},
                    seed=self.seed,
                    run=run,
                    condition_label=option,
                    variable_label="base",
                    settings=self.overwrite_settings.apply(),
                )

    def commands(self) -> Generator[Command, None, None]:
        if not self.variables:
            yield from self._no_variable_runs()
            return
        product_combinations = product(
            *(variable.values for variable in self.variables)
        )

        for combination in product_combinations:
            for option, conditions in self.conditions.items():
                for run in range(self.number_of_runs):
                    yield Command(
                        conditions=conditions,
                        main_directory=self.directory,
                        variables=dict(
                            zip(
                                [variable.name for variable in self.variables],
                                combination,
                            )
                        ),
                        seed=self.seed,
                        run=run,
                        condition_label=option,
                        variable_label="_".join(
                            variable.name for variable in self.variables
                        ),
                        settings=self.overwrite_settings.apply(),
                    )

    def __len__(self) -> int:
        return (
            reduce(operator.mul, (len(variable.values) for variable in self.variables))
            * self.number_of_runs
            * len(self.conditions)
        )


def run_experiments(
    configuration: Configuration,
) -> None:
    with WorkerPool() as pool:
        pool.map(
            Command.execute,
            configuration.commands(),
            iterable_len=len(configuration),
            progress_bar=True,
        )
