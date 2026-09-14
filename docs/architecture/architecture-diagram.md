# Architecture diagram

```mermaid
flowchart LR
  subgraph inputs [Inputs]
    T[topology.json + tag_boosts]
    F[findings.json + kev + epss]
  end

  subgraph core [src/vuln_reachability_scorer]
    L[loaders]
    G[graph / paths]
    S[scoring + tag boosts + KEV + EPSS]
    A[asset_report]
    E[explain / summary]
    C[cli]
  end

  subgraph out [Output]
    R[table / JSON / CSV / SARIF]
  end

  subgraph automation [GitHub]
    CI[python-ci.yml@v0.2.0]
  end

  T --> L
  F --> L
  L --> G
  G --> S
  S --> E
  L --> A
  A --> C
  E --> C
  S --> C
  C --> R
  CI -.->|pytest on PR| core
```

CLI flags that shape scoring/output: `--asset-report`, `--explain`, `--summary`, `--strict`, `--fail-under`, `--only-kev`, `--show-title`, `--min-priority`, `--limit`, `--format`, `--output`.
