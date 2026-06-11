# Building deadman-10

A dead-man switch is only as trustworthy as the binary running it (threat model
D4): a swapped binary defeats every other control. This documents how to build
`dms` reproducibly and audit its dependencies.

## Build

```bash
go build -trimpath -o bin/dms ./cmd/dms
```

- **`-trimpath`** removes local filesystem paths from the binary, so the output
  doesn't depend on *where* it was built — a prerequisite for reproducibility.
- The Go toolchain version is pinned in `go.mod` (`go 1.24.0`). Build with a
  matching toolchain for byte-identical output.
- All dependencies are pinned by `go.sum`; `GOFLAGS=-mod=readonly` (the default in
  recent Go) fails the build if `go.mod`/`go.sum` would change.

## Dependency audit (do this before trusting a build)

The security-critical goal is a small, auditable dependency tree. In particular
the Arweave client is **standard-library only** — it does NOT pull in the heavy
`goar` SDK (which drags in go-ethereum + gorm). Verify:

```bash
# Must print nothing — none of these belong in the binary:
go list -deps ./cmd/dms | grep -iE 'go-ethereum|/gorm|everfinance|/goar$|hashicorp/vault'

# Review the full external (non-stdlib) dependency set:
go list -deps ./cmd/dms | grep -E '^[a-z0-9.-]+\.[a-z]+/'
```

Expected external modules: `filippo.io/age` (vault encryption), `crypto/ed25519`
(stdlib, owner signing), and the drand stack (`drand/tlock`, `drand/kyber`,
`drand/drand`) plus its transitive gRPC/protobuf — required only for the timelock
leg. Nothing else should appear.

## Tests

```bash
go test ./...                                      # fast unit + CLI suite
go test -tags=integration ./internal/timelock/     # live drand round-trip
DMS_INTEGRATION=1 go test ./cmd/dms/               # live arm/recover/re-arm + Arweave (needs `npx arlocal 1985`)
```

## Release signing — DEFERRED

A real release should ship **signed** binaries (cosign or minisign) so users can
verify provenance. This is **not yet set up**: there is no published repository to
attach a release pipeline to. Until signed releases exist, build from source and
run the dependency audit above. When the repo is published, add:

- a `cosign`/`minisign` signature per release artifact,
- the public key in this file and the README,
- a CI job (`.github/workflows/`) that builds with `-trimpath`, runs the audit,
  and signs — so the published binary matches a reproducible source build.
