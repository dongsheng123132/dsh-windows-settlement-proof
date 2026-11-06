# dsh-windows-settlement-proof

**Maintainer / Author：He Fangsheng (贺方升 / 贺去病; Dosen) · [hequbing.com](https://www.hequbing.com)**

Offline, content-addressed evidence that an approved Windows control-plane change actually settled across every required surface. It compares explicit redacted receipts for Service Control Manager, Task Scheduler, Event Log and policy projections against a fixed hash lock, chronology, freshness and restart-epoch policy.

This is a verifier, not an operator. It never runs PowerShell, `sc.exe`, registry commands or arbitrary subprocesses; it never reads Windows services, task definitions, Event XML or business payloads. Reports contain only public counts, booleans and SHA-256 values.

## Boundary

- `dsh-windows-readiness-proof` asks whether a Windows host satisfies prerequisites before work begins.
- `dsh-decision-effect-proof` provides generic authorization/effect linkage.
- This plugin asks whether one approved Windows control-plane change converged across domain-specific surfaces, remained present at a required restart epoch, and has a matching success-event receipt.

It does not create a second action core and does not execute changes.

## Manifest

The manifest pins a redacted target identity, target revision, request, approval and desired-state hashes; an expected state hash for each required surface; bounded observation receipts; an evaluation time; freshness; and the minimum restart epoch. See [`examples/settled.json`](examples/settled.json).

## Use

```bash
npm test
npm run check
node bin/dsh-windows-settlement-proof.mjs verify examples/settled.json
dsh plugin --profile proof add .
```

DSH tools:

- `dsh_windows_settlement_inspect`: inline, read-only metadata inspection.
- `dsh_windows_settlement_verify`: verifies a workspace-relative manifest and writes one content-addressed report only beneath an explicit workspace-relative `artifactDir`.

MCP tools expose inline inspection and verification without filesystem writes. The CLI exits `0` for settled, `1` for a valid but unsettled verdict, and `2` for invalid input or usage.

## Safety

Manifest and artifact paths reject absolute paths, traversal and symlinks. Secret-shaped values and credential-named scalar fields are rejected. Artifact writes use exclusive creation, deterministic content addressing and read-back SHA-256 verification.

MIT licensed. See [SECURITY.md](SECURITY.md).
