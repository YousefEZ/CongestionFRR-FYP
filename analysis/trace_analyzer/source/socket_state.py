from collections import defaultdict
from dataclasses import dataclass, field
from typing import NamedTuple




class SackedByteRange(NamedTuple):
    start: int
    end: int


@dataclass
class SocketState:
    high_tx_mark: int = field(default=0)
    last_acked_seq: int = field(default=0)
    dup_ack: int = field(default=0)
    high_sacked_seq: int = field(default=0)
    sacked_bytes: list[SackedByteRange] = field(default_factory=list)
    sack_dupacks: defaultdict[int, int] = field(
        default_factory=lambda: defaultdict(int)
    )
