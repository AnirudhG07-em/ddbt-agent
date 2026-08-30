# em-bash × ddbt guard — session survey (120 sessions)

## Guard ON
  BENIGN (want allow)        allow 99.4%  ask  0.6%  override  0.0%  deny  0.0%   (n=1859)
  SENSITIVE READ (ask ok)    allow 24.7%  ask 68.0%  override  7.2%  deny  0.0%   (n=97)
  NEW-HOST curl              allow  0.0%  ask 100.0%  override  0.0%  deny  0.0%   (n=18)
  EXFIL (want flag)          allow  0.0%  ask 20.0%  override 80.0%  deny  0.0%   (n=25)
  DESTRUCTIVE (want flag)    allow  0.0%  ask  0.0%  override 100.0%  deny  0.0%   (n=10)

  >>> BENIGN FALSE-POSITIVE (bother) rate: 11/1859 = 0.6%
  >>> HIDDEN multi-step exfil chains caught (deny/override at the send): 13/13
  >>> Threats (exfil+destructive) MISSED (allowed): 0

## Guard OFF (baseline — what would just run)
  BENIGN                     allow 100.0%  ask  0.0%  override  0.0%  deny  0.0%   (n=1859)
  SENSITIVE READ             allow 100.0%  ask  0.0%  override  0.0%  deny  0.0%   (n=97)
  EXFIL                      allow 100.0%  ask  0.0%  override  0.0%  deny  0.0%   (n=25)
  DESTRUCTIVE                allow 100.0%  ask  0.0%  override  0.0%  deny  0.0%   (n=10)

  >>> With NO guard, all 35 exfil+destructive actions run unflagged (0 caught).

## Top benign commands still flagged (guard ON)
     5x  mkdir -p build/out
     3x  ./scripts/deploy.sh
     2x  curl https://api.github.com/repos/a/b
     1x  source .venv/bin/activate

## Why (checkpoint/effect)
    11x  elevated-gate/ask

---

## Tunings APPLIED (this survey drove them)
1. `is_external` wildcard/apex bug — `*.npmjs.org` didn't match `registry.npmjs.org`, and `*.pypi.org`
   didn't cover apex `pypi.org`; also a loose `endswith` could trust `evilnpmjs.org`. Fixed → the pypi/npm
   curl false-positives vanished. (biggest win: 9.7%→1.8%)
2. Content-sensitivity used ALL 17 MITRE tactics — `cat package.json` (supply_chain), `whoami`
   (discovery) tripped the yellow gate. Restricted to DATA tactics {exfiltration, secret_theft,
   surveillance, financial_harm}.
3. `.sh`/`.h`/`.key`/media extensions weren't in the file-extension set, so `deploy.sh` was misread as a
   host (`.sh` is a real TLD) → net_semantic false ASK on `chmod +x deploy.sh`. Added them. (1.8%→0.6%)

## Remaining bother (0.6%) = adaptive strictness only
Every residual benign flag is `elevated-gate/ask`: a benign command gated because the SAME session
already ran a real exfil/destructive action, so suspicion elevated. This is the self-tightening security
feature working as designed — but it means a *testing* session that deliberately triggers threats will
then gate benign work. OPEN DECISION: soften adaptive strictness in shell mode (raise the elevate/lock
thresholds) if smoother manual testing is preferred over self-tightening.

## Verdict distribution notes
- EXFIL: 80% override / 20% ask — all flagged; single-command sensitive sends land on ask (content), the
  read→stage→send chains land on override (killchain). All overridable (deny_mode=override), never silent.
- DESTRUCTIVE: 100% override. NEW-HOST curl: 100% ask (a one-time per-host confirm; tune if too chatty).
