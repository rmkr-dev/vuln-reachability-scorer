# Architecture diagram

```mermaid
flowchart LR
  subgraph inputs [Inputs]
    T[examples or user topology.json]
    F[findings.json]
  end

  subgraph core [src/vuln_reachability_scorer]
    L[loaders]
    G[graph hop distance]
    S["scoring base x R x E"]
    C[cli]
  end

  subgraph out [Output]
    R[table or JSON]
  end

  subgraph automation [GitHub]
    CI[python-ci.yml@v0.2.0]
  end

  T --> L
  F --> L
  L --> G
  G --> S
  S --> C
  C --> R
  CI -.->|pytest on PR| core
```
