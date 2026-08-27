# sift — a non-LLM semantic sandbox for agent actions

`sift` classifies each agent tool-call **good / bad** without an LLM, as a drop-in alternative to
the ddbt LLM step-judge. It fuses a tiny **static embedding** (≤100 MB, not an SLM) with
**deterministic structural/taint features**, then decides **DENY / ASK / ALLOW** with a calibrated,
conformal band.

This is a **bake-off**: seven methods, one harness, ranked on a **shift/adversarial** test — not just
in-distribution — because semantic detectors look great in-dist and collapse under paraphrase/encoding
([arXiv:2504.11168](https://arxiv.org/abs/2504.11168)). See `CITATIONS.md` for every method's source.

## Why this shape

"Bad" factorises, and only part is semantic:
- **Semantic** (harm, secrecy, payload-sensitivity) → the embedding's job.
- **Structural / data-flow** (provenance, exfil-shape, scope, blast-radius) → deterministic code
  (`sift/features/structural.py`), optionally sourced from **ddbt's own** provenance + grant floor
  (`sift/features/ddbt_bridge.py`).

An embedding *cannot* tell whether a value was chosen by you or by an injection — that's origin, not
meaning — so the exfil guarantee lives in the structural layer, exactly as in ddbt.

## The seven methods

| # | method | encoder | head | note |
|---|--------|---------|------|------|
| 1 | `static_linear` | static | logistic | fast floor |
| 2 | `static_gbt` | static | grad-boosted trees | NemoGuard / XGBoost pattern |
| 3 | `prototypes` | static | nearest-centroid cosine | zero-shot, interpretable, extensible |
| 4 | `setfit` | MiniLM | contrastive + head | best few-shot accuracy |
| 5 | `model2vec_trained` | static | trainable head | trains the embedding, stays ~30 MB |
| 6 | `anomaly` | static | Mahalanobis to benign | catches novel attacks |
| 7 | `fusion` | static | GBT over `[emb ‖ structural]` | **the product** — ensemble defence |

## Run it

```bash
# offline, zero downloads (hashing encoder + sklearn methods 1,2,3,6,7):
uv run --directory sift --no-project --with numpy --with scikit-learn python train_all.py --encoder hashing

# the real static embedder (downloads potion-base-32M, ~30 MB):
uv run --directory sift --extra embed python train_all.py --encoder model2vec

# add the fine-tuners (SetFit, Model2Vec-trained):
uv run --directory sift --extra all python train_all.py --encoder model2vec
```

Output: a leaderboard ranked by **shift recall@5%FPR** and a JSON report in `sift/reports/`.

### The real benchmarks

```bash
./run_benches.sh                 # R-Judge + InjecAgent + MCPTox, real static encoder
./run_benches.sh hashing         # offline
```

Loads `bench/data/{rjudge,injecagent,mcptox}` from the parent repo with the **same label parsing as
the ddbt bench** (`sift/data/benches.py`), so numbers sit next to ddbt's LLM-judge results (R-Judge
F1 91.5% · InjecAgent 100% · MCPTox 99.8%). Each set is split train/test, plus an **adversarial-shift**
test (`synth.harden`: paraphrase + benign-framing + base64/ROT13/homoglyph/zero-width).

Two data-quality corrections vs a naive run:
- **MCPTox benign control** — the bench ships 485 poisoned vs only 8 clean descriptions, so FPR was
  unmeasurable. `sift/data/tool_descriptions.py` adds a balanced benign corpus **including hard
  negatives** (legitimate security/pre-authorization framing), so specificity is real.
- **Harder shift** — attacks are wrapped in benign business framing and encoded; a fraction of benign
  gets surface noise, so "clean surface ⇒ benign" isn't a free shortcut. `injecagent_prov` is the
  honest stressor: the *same* instruction labeled bad (arrived via a tool output) vs benign (the user
  asked for it) — only **provenance** separates them.

Metrics report `specificity@f1thr` and `n_benign` alongside F1, so an imbalanced set can't hide a
weak false-positive rate.

## Layout
```
sift/
  features/  text.py (decode+tag)  embed.py (encoders)  structural.py (taint)  ddbt_bridge.py
  data/      taxonomy.py (the "bad" catalog)  synth.py (corpus)  dataset.py
  methods/   embed_heads.py (1,2,3,6)  finetuned.py (4,5)  fusion.py (7)
  eval/      metrics.py  calibrate.py (Platt/isotonic + conformal)  harness.py
  train_all.py   eval_all.py
```

The seed corpus in `data/synth.py` is a placeholder to make the harness runnable today; real labels
come from the ddbt benches (R-Judge / InjecAgent / AgentDojo / MCPTox) and from distilling the ddbt
LLM judge — see the roadmap note in `synth.py`.
