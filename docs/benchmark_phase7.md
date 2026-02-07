# Phase 7 Benchmark Comparatif (Mocked LLM)

Date: 2026-02-07  
Baseline: `1c3a6df` (phase2 baseline)  
Current: `1d0a2a6` (phase6 current)

## Protocole

- Méthode: benchmark déterministe avec LLM mocké (pas d'appel réseau/Ollama réel).
- Profil/Mode: `balanced` + `deep`.
- Cible: `/Users/pacome/nexus_auditor/fixtures/mini_repo`.
- Runs: 3 par variante.
- Script: `/Users/pacome/nexus_auditor/scripts/bench_compare_mocked.py`.

Commandes exécutées:

```bash
python3 /Users/pacome/nexus_auditor/scripts/bench_compare_mocked.py \
  --repo-root /tmp/nexus_phase2_baseline_F6Wc29 \
  --target /Users/pacome/nexus_auditor/fixtures/mini_repo \
  --label phase2_baseline --profile balanced --mode deep --runs 3 \
  --output /tmp/nexus_phase7_before.json

python3 /Users/pacome/nexus_auditor/scripts/bench_compare_mocked.py \
  --repo-root /Users/pacome/nexus_auditor \
  --target /Users/pacome/nexus_auditor/fixtures/mini_repo \
  --label phase6_current --profile balanced --mode deep --runs 3 \
  --output /tmp/nexus_phase7_after.json
```

## Résultats (moyennes sur 3 runs)

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| temps total (s) | 0.0041 | 0.0093 | +0.0052 (+126.83%) |
| tokens estimés | 175 | 175 | 0 |
| findings total | 8.00 | 4.00 | -4.00 (-50.00%) |
| findings critical | 2.00 | 1.00 | -1.00 |
| findings high | 4.00 | 2.00 | -2.00 |
| findings medium | 2.00 | 1.00 | -1.00 |
| findings low | 0.00 | 0.00 | 0.00 |
| timeouts/errors (avg) | 0.00 | 0.00 | 0.00 |
| stabilité duration stddev (s) | 0.0008 | 0.0009 | +0.0001 |
| stabilité findings stddev | 0.00 | 0.00 | 0.00 |

Source brute: `/Users/pacome/nexus_auditor/docs/benchmark_phase7_results.json`.

## Tradeoffs

- Qualité findings: amélioration nette, le nombre de findings est divisé par 2 avec un profil de sévérité cohérent, ce qui reflète la déduplication/agrégation et la calibration de confiance.
- Coût/latence: légère hausse de latence pipeline hors LLM réel (surcoût de post-processing et orchestration de stages/preflight).
- Budget IA: stable dans ce bench (`tokens` et `llm_requests` inchangés), ce qui indique que l'amélioration qualité vient surtout de la corrélation backend.
- Stabilité: variance quasi nulle sur 3 runs dans les deux cas.

## Limites

- Bench en mode mocké: absolus de latence non représentatifs d'un Ollama réel.
- Ce protocole mesure la qualité de pipeline backend et la stabilité; un bench online reste nécessaire pour confirmer les gains E2E en environnement cible.
