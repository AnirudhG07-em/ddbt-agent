"""Turn raw action records into the arrays every method consumes.

One place owns the mapping record → (rendered text, structural feature row, label), so all seven
methods see identical inputs and the bake-off is apples-to-apples.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from sift.features import structural
from sift.features.text import decode_and_normalise, render_action


@dataclass(slots=True)
class Dataset:
    records: list[dict]
    texts: list[str]              # rendered, tagged, decoded — what the encoder embeds
    struct: np.ndarray            # (n, len(FEATURE_NAMES)) deterministic features
    y: np.ndarray                 # (n,) 0/1 bad label
    domains: list[str]
    categories: list[str]

    def __len__(self) -> int:
        return len(self.records)


def to_dataset(records: list[dict], trusted_domains: tuple[str, ...] = ("acme.com",)) -> Dataset:
    texts, structs, ys, doms, cats = [], [], [], [], []
    for r in records:
        # A record is EITHER a structured tool call ({tool,args,...}) OR a pre-rendered blob
        # ({text}) — R-Judge trajectories and MCPTox tool-descriptions are the latter. Both paths
        # end in (rendered text, structural row) so every method sees one uniform input.
        if r.get("text") is not None:
            args_norm = decode_and_normalise(str(r["text"]))
            texts.append(args_norm)
            tool = r.get("tool", "")
        else:
            args_norm = decode_and_normalise(str(r.get("args", "")))
            texts.append(render_action(r["tool"], r.get("args", ""), goal=r.get("goal", ""),
                                       history=r.get("history", ""),
                                       sink_provenance=r.get("sink_provenance", "unknown")))
            tool = r["tool"]
        structs.append(structural.extract(
            tool, args_norm, sink_provenance=r.get("sink_provenance", "unknown"),
            trusted_domains=trusted_domains).vector())
        ys.append(int(r.get("label", 0)))
        doms.append(r.get("domain", "?"))
        cats.append(r.get("category", "?"))
    return Dataset(records, texts, np.vstack(structs) if structs else np.zeros((0, len(structural.FEATURE_NAMES))),
                   np.asarray(ys, dtype=np.int64), doms, cats)
