# References

Background material that informed the scoring model. None of these are runtime dependencies.

| Resource | Why it matters |
| --- | --- |
| [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document) | Defines the usual `base_score` scale this tool reweights |
| [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Motivates prioritization beyond raw CVSS (exploitation signal; not consumed by this CLI yet) |
| [NIST SP 800-40](https://csrc.nist.gov/publications/detail/sp/800-40/rev-4/final) | Guide for vulnerability management programs where reachability context is expected |

Future work may optionally ingest KEV membership as an additional factor; that would need a new ADR.

| [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Motivates optional `kev` finding flag ([ADR-003](../decisions/ADR-003-kev-multiplier.md)); catalog is not fetched by this CLI |
| [FIRST EPSS](https://www.first.org/epss/) | Motivates optional `epss` finding field ([ADR-004](../decisions/ADR-004-epss-factor.md)); scores are not fetched by this CLI |

## Config tooling

- [Config key reference](../schemas/config.md)
- [Draft JSON Schema](../schemas/vrscore.schema.json) for editors (not loaded at runtime)
- [ADR-007](../decisions/ADR-007-config-first-cli.md) / [ADR-008](../decisions/ADR-008-config-extends.md)
