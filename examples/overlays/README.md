# Overlay configs

Configs in this directory `extends` parents under `examples/` (e.g. `../vrscore-base.toml`).

Relative `topology` / `findings` / `output` keys in the **base** still resolve against the base file’s directory — not this folder — so estate paths stay next to the shared base ([ADR-008](../../docs/decisions/ADR-008-config-extends.md)).

| File | Extends | Intent |
| --- | --- | --- |
| `vrscore-ci.toml` | `../vrscore-base.toml` | Quiet SARIF + `fail_under` from a subdirectory |
| `vrscore-strict-ci.toml` | `vrscore-ci.toml` | Same CI gate with `strict = true` (three-layer chain) |

```bash
vrscore -c examples/overlays/vrscore-ci.toml -o /tmp/reachability.sarif
vrscore -c examples/overlays/vrscore-strict-ci.toml -o /tmp/reachability.sarif
```

Prefer this pattern over long CLI flag chains ([ADR-007](../../docs/decisions/ADR-007-config-first-cli.md)).
