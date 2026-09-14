# Architecture docs

| Doc | Purpose |
| --- | --- |
| [architecture.md](architecture.md) | Current-state narrative of this CLI |
| [architecture-diagram.md](architecture-diagram.md) | Mermaid view of inputs → score → output |

Reachability uses a single multi-source BFS from ingress (`all_hop_distances` / `all_shortest_paths`) so large graphs stay O(V+E).
