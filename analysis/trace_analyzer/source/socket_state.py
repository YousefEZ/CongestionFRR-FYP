from collections import defaultdict
from dataclasses import dataclass, field
from typing import NamedTuple


class SackedByteRange(NamedTuple):
    start: int
    end: int


@dataclass
class SocketState:
    time: float = field(default=0)
    high_tx_mark: int = field(default=0)
    high_rtx: int = field(default=0)
    recovery_point: int = field(default=0)
    in_recovery: bool = field(default=False)
    last_acked_seq: int = field(default=0)
    dup_ack: int = field(default=0)
    high_sacked_seq: int = field(default=0)
    sacked_bytes: list[SackedByteRange] = field(default_factory=list)
    sack_dupacks: defaultdict[int, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    last_sent_timestamps: dict[int, float] = field(default_factory=dict)
    last_send_timestamp: float = field(default=0)
    last_ack_timestamp: float = field(default=0)
    scoreboard: set[int] = field(default_factory=set)
