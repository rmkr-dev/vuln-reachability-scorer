# Architecture diagram

Current foundation is docs-only. The Mermaid diagram below is the **intended** CLI shape; boxes marked *(planned)* are not yet in the tree.

```mermaid
flowchart LR
  subgraph inputs [Inputs]
    T[topology.json]
    F[findings.json]
  end

  subgraph core [CLI / library - planned]
    L[Load and validate]
    G[Build asset graph]
    S[Score: base x R x E]
  end

  subgraph out [Output - planned]
    R[Ranked table / JSON]
  end

  T --> L
  F --> L
  L --> G
  G --> S
  S --> R
```

When the package ships, update this diagram so every box maps to a real module path.
