# Citations — methods & papers `sift` builds on

Every technique here maps to a source. Inline citations also live in each module's docstring.

## Encoders (≤100 MB, none an SLM)
- **Model2Vec / potion-base-32M** — static (non-transformer) embeddings, ~30 MB, ~500× faster on CPU. MinishLab, 2024. https://github.com/MinishLab/model2vec
- **Sentence-BERT / all-MiniLM-L6-v2** — small transformer encoder, SetFit base. Reimers & Gurevych, *Sentence-BERT*, EMNLP 2019, arXiv:1908.10084.
- **Feature hashing** (offline fallback encoder) — Weinberger et al., *Feature Hashing for Large Scale Multitask Learning*, ICML 2009, arXiv:0902.2206.

## Heads / methods
1. **Encoder + logistic regression** — the embedding+linear guardrail pattern.
2. **Encoder + gradient-boosted trees** — cf. NVIDIA **NemoGuard-JailbreakDetect** (random forest on embeddings) and the **embedding + XGBoost** injection detector (97.7% F1 @ ~1µs/sample), CEUR-WS Vol-3920 paper15. GBT: Chen & Guestrin, *XGBoost*, KDD 2016, arXiv:1603.02754.
3. **Nearest-centroid prototypes** — Rocchio / centroid text classification (Manning, Raghavan & Schütze, *IIR* ch. 14); **Prototypical Networks**, Snell et al., NeurIPS 2017, arXiv:1703.05175.
4. **SetFit** — contrastive Siamese fine-tune + head, few-shot, prompt-free. Tunstall et al., *Efficient Few-Shot Learning Without Prompts*, arXiv:2209.11055.
5. **Model2Vec trained classifier** — trainable head over static embeddings. MinishLab, 2025.
6. **Anomaly / Mahalanobis OOD** — Lee et al., *A Simple Unified Framework for Detecting OOD Samples*, NeurIPS 2018, arXiv:1807.03888; covariance shrinkage: Ledoit & Wolf, 2004.
7. **Fusion (embedding ⊕ structural)** — ensemble defence recommended by *Bypassing LLM Guardrails: An Empirical Analysis of Evasion Attacks*, arXiv:2504.11168; DLP practice (content + context + taint), Cyberhaven / Lakera.

## Evaluation
- **AUPRC under imbalance** — Davis & Goadrich, ICML 2006.
- **Selective classification / abstention** — Geifman & El-Yaniv, arXiv:1705.08500.
- **Conformal prediction** (DENY/ASK/ALLOW bands) — Angelopoulos & Bates, *A Gentle Introduction to Conformal Prediction*, arXiv:2107.07511.
- **Calibration** — Platt scaling (Platt, 1999); Isotonic (Zadrozny & Elkan, KDD 2002); Guo et al., *On Calibration of Modern Neural Networks*, arXiv:1706.04599.
- **Distribution-shift caveat** — the shift/adversarial regime exists because in-distribution scores mislead; cf. evasion analysis (arXiv:2504.11168).

## Structural / anti-injection lineage (shared with ddbt)
- **Capability ticket / least privilege for agents** — SAGA, arXiv:2504.21034.
- Provenance ("could a stranger have chosen this value?") and quarantine are ddbt's own, reused here via `sift.features.ddbt_bridge`.
