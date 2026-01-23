from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .signal_catalog import SignalDef


@dataclass(frozen=True)
class CatalogIndex:
    by_name: Dict[str, SignalDef]

    @staticmethod
    def from_catalog(catalog: List[SignalDef]) -> "CatalogIndex":
        return CatalogIndex(by_name={s.name: s for s in catalog})

    def subset(self, names: List[str]) -> List[SignalDef]:
        out: List[SignalDef] = []
        for n in names:
            try:
                out.append(self.by_name[n])
            except KeyError as e:
                raise KeyError(f"signal not found in catalog: {n}") from e
        return out
