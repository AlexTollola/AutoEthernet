from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence

from autoeth.core.config import SignalDef


@dataclass(frozen=True)
class SignalIndex:
    by_name: Dict[str, SignalDef]

    @staticmethod
    def from_signals(signals: Sequence[SignalDef]) -> "SignalIndex":
        return SignalIndex(by_name={s.name: s for s in signals})

    def subset(self, names: Sequence[str]) -> List[SignalDef]:
        out: List[SignalDef] = []
        for n in names:
            try:
                out.append(self.by_name[n])
            except KeyError as e:
                raise KeyError(f"signal not found in catalog: {n}") from e
        return out

