from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

import yaml


@dataclass(frozen=True)
class SignalDef:
    name: str
    type: str  # u8,u16,u32,i8,i16,i32,f32
    scale: float = 1.0
    offset: float = 0.0
    unit: str = ""
    default: float = 0.0


def load_catalog(path: str | Path) -> List[SignalDef]:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    sigs = data.get("signals", [])
    out: List[SignalDef] = []
    for s in sigs:
        out.append(
            SignalDef(
                name=str(s["name"]),
                type=str(s["type"]),
                scale=float(s.get("scale", 1.0)),
                offset=float(s.get("offset", 0.0)),
                unit=str(s.get("unit", "")),
                default=float(s.get("default", 0.0)),
            )
        )
    return out
