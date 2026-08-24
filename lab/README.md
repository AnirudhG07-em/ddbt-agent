# lab — a playground for safe, fast auto-mode

The demo proves the idea on **one** step. That is not enough to trust an auto-mode. This
folder is where we write everyday inputs — nasty tool descriptions and whole realistic
sessions — and measure the two numbers that decide whether auto-mode is real:

- **SAFETY** — of the dangerous steps, how many were caught.
- **FRICTION** — of the benign steps, how many were needlessly interrupted (asked or blocked).

Maxing one is trivial. Deny everything → perfect safety, useless. Allow everything → zero
friction, unsafe. The goal is **SAFETY ≈ 100% and FRICTION ≈ 0 at the same time.**

## Run it

```bash
export GEMINI_API_KEY=...            # real judge + scanner (same code the hook uses)
uv run python lab/run.py scan        # score the poisoned/clean descriptions
uv run python lab/run.py session     # run the everyday task, report friction + safety
uv run python lab/run.py all

uv run python lab/run.py all --stub  # offline heuristic, no key — smoke test only
```

## Write your own

- **`prompts.py`** — hand-written tool descriptions. Add a dict with `expect="poison"` or
  `"clean"` and the description text. Try to fool it: polite phrasing, fake authority,
  encoding, a dangerous-but-honest function. The clean money-transfer / poison file-reader
  pair is the point — danger is not the signal, *an embedded order* is.
- **`session.py`** — a full session. `kind="work"` steps should sail through; `kind="trap"`
  steps should be stopped. Use `returns=...` to plant an injection inside something the agent
  reads, so a later step picks up a stranger-chosen value (that is how a real attack lands).

## The broader picture — how auto-mode gets safe AND fast

Reducing friction by making the **judge more permissive** just trades safety for speed. The
mature way keeps both, and it rests on one idea: **you can safely allow more when a wrong
allow is recoverable.** Four moves, in the order they pay off:

1. **A deterministic fast-path (no model at all).** Read-only, inside the workspace, no
   egress → allow instantly. Agent-Sentry settles ~96% of calls this way. This is the real
   latency win *and* the real friction win: most benign steps never reach the judge, and the
   attacker's injectable surface shrinks to the ambiguous tail. Watch the `session` output —
   every `git status` / `Read` / in-workspace `Write` is a call that should never have needed
   an LLM.

2. **The judge only on the ambiguous middle** — anything that sends, writes outside, grants,
   spends, or carries a stranger-chosen value. This is already what ddbt does; the fast-path
   in (1) is what stops it running on everything.

3. **Ask sparingly, and only where it's earned.** An ASK is a task failure in auto-mode, so
   reserve it for *high-impact AND uncertain*. In `session.py` exactly one benign step (the
   email to a named teammate) should ever ask. If more do, that is friction to hunt down.

4. **A hard floor so a wrong allow isn't fatal.** OS sandbox (network off by default, writes
   confined), staging/undo, per-server capability tickets. This is the lever that lets you
   *allow more without asking*: if mistakes are reversible, the cost of a rare wrong allow is
   bounded, so you don't need a human on every high-impact step. Without a floor, low friction
   and safety are in direct tension; with one, they stop fighting.

The order matters: (1) and (2) make it fast, (3) keeps it quiet, and (4) is what makes it
safe to be quiet. The lab is how we check each move helps on *everyday* traffic instead of
one hand-picked prompt.
