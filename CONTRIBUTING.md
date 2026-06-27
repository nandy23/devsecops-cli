# Contributing to devsec

Thanks for helping build the open source DevSecOps assistant! Most contributions
need **no Go code** — rules and tool knowledge are data.

## Ways to contribute

### Add or change a recommendation rule (no code)
Rules live in [`rules/`](rules/) as YAML. Each rule matches the `Analysis` and
emits a tool recommendation. Copy an existing rule, change the `when` condition
and `recommend` block, and open a PR. Conditions compose with `all` / `any` /
`not` and leaf predicates (`tech.kind`, `tech.name`, `coverage.category`,
`coverage.state`).

### Add a tool to `explain` (no code)
Add an entry to [`knowledge/tools.yaml`](knowledge/tools.yaml) with purpose,
advantages, when-to-use, alternatives and pipeline stage.

### Add a detector, generator, auditor or connector (Go)
Implement the relevant interface from [`pkg/pluginsdk`](pkg/pluginsdk) (or the
corresponding port in `internal/domain/port`) and register it in
`internal/di`. Keep files small and add a unit test.

## Ground rules

- **devsec orchestrates, it never bundles or executes scanners.** PRs that shell
  out to run a scanner will be declined.
- Keep the dependency rule: `domain` imports nothing; `infra`/`cli` depend
  inward; only `internal/di` wires concrete types.
- Add tests. Prefer table-driven unit tests and golden files for generators.

## Local workflow

```bash
make fmt vet test
make run
```

## Commit / PR

- Small, focused PRs.
- Describe the security rationale for new rules.
- Run `make all` before pushing.
