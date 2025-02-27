from dataclasses import dataclass
import os
from typing import Generator
from itertools import product

from mpire.pool import WorkerPool
from pydantic import BaseModel

NUM_PROCESSES = 4


class BaseSettings(BaseModel):
    bandwidth_primary: str
    bandwidth_alternate: str
    delay_primary: str
    delay_alternate: str
    tcp_senders: int
    tcp_bytes: int
    udp_start_time: float
    udp_segment_size: int


@dataclass(frozen=True)
class Command:
    fast_rerouting: bool
    congestion: bool
    main_directory: str
    variables: dict[str, str]
    seed: int
    run: int
    condition_label: str
    variable_label: str

    @property
    def directory(self) -> str:
        return os.path.join(
            self.main_directory,
            self.variable_label,
            self.condition_label,
            f"{self.seed}{self.run}",
            "_".join((value for value in self.variables.values())),
        )

    def generate_dir(self) -> None:
        if os.path.exists(self.directory):
            os.rmdir(self.directory)
        os.makedirs(self.directory)

    def options(self) -> list[str]:
        command_options = []
        for key, value in self.variables.items():
            command_options.append(f"--{key}={value}")

        command_options.append(f"--dir={self.directory}/")
        command_options.append(f"--seed={self.seed}")
        command_options.append(f"--run={self.run}")

        if self.fast_rerouting:
            command_options.append("--enable-rerouting")
        if self.congestion:
            command_options.append("--enable-udp")

        return command_options

    def generate(self) -> str:
        return 'NS_LOG="" ./ns3 run "scratch/simulation.cc {}" 2> {}/debug.log'.format(
            " ".join(self.options()), self.directory
        )

    def execute(self) -> None:
        self.generate_dir()
        os.system(self.generate())


class Conditions(BaseModel):
    fast_rerouting: bool
    congestion: bool


class Variable(BaseModel):
    name: str
    values: list[str]


class Configuration(BaseModel):
    variables: list[Variable]
    directory: str
    conditions: dict[str, Conditions]
    seed: int
    number_of_runs: int

    def commands(self) -> Generator[Command, None, None]:
        product_combinations = product(
            *(variable.values for variable in self.variables)
        )

        for combination in product_combinations:
            for run in range(self.number_of_runs):
                for option, condition in self.conditions.items():
                    yield Command(
                        fast_rerouting=condition.fast_rerouting,
                        congestion=condition.congestion,
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
                    )


def run_experiments(
    configuration: Configuration,
) -> None:
    with WorkerPool(n_jobs=NUM_PROCESSES) as pool:
        pool.map(
            Command.execute,
            configuration.commands(),
            progress_bar=True,
        )


if __name__ == "__main__":
    variables = [
        Variable(name="delay_alternate", values=[f"{i}ms" for i in range(10, 101, 10)]),
    ]
    directory = "results"
    conditions = {"congested": Conditions(fast_rerouting=False, congestion=True)}
    runs = 10
    seed = 42

    run_experiments(
        Configuration(
            variables=variables,
            directory=directory,
            conditions=conditions,
            seed=seed,
            number_of_runs=runs,
        )
    )
