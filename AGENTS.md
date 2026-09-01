# Repository Engineering Gates

These instructions apply to every change in this repository. Treat this library as security-sensitive infrastructure: it crosses Go, cgo, PKCS#11 modules, and external HSM ownership boundaries.

## Required evidence before completion

Do not report a change as complete until its production path, tests, and benchmark evidence have been identified. In the final handoff, report the exact commands run, their outcome, and any validation that could not run.

For every code change:

1. Map the changed helper to the exported API and production call path that uses it. Do not optimize test-only code and describe it as a production improvement.
2. Add or update a reproducible benchmark that exercises that production path. Capture a before and after result under equivalent conditions, including `ns/op`, `B/op`, and `allocs/op`.
3. Add regression tests for observable behavior and for the ownership or lifetime invariant affected by the change.
4. Run the correctness, race, static-analysis, and memory-safety gates below.

For documentation-only, comment-only, test-only, or build-metadata changes, explicitly state why a runtime benchmark is not applicable. Still run the smallest relevant correctness and static checks. Never invent benchmark results.

## Benchmark policy

- Use Go benchmarks with `b.ReportAllocs()` and `b.Loop()` for new benchmarks.
- Benchmark the exported API or the closest production-path entry point, not an isolated helper unless the helper itself is the subject of the claim.
- Use realistic cardinality and payload sizes. For lookup code, include a populated-token case; for crypto operations, include representative message or digest sizes; for pooled/session code, include contention when relevant.
- Run enough samples to distinguish the result from noise. Prefer at least five samples and compare them with `benchstat` when available. If `benchstat` is unavailable, report every sample or clearly label a single run as preliminary.
- Keep machine, Go version, PKCS#11 implementation/HSM, token population, benchmark duration, and relevant configuration identical between baseline and candidate.
- Run HSM benchmarks only against an isolated benchmark token. Benchmark setup must not alter a production token and must clean up objects it creates.
- A performance change is accepted only when the measured production-path metric improves without a material regression in another relevant metric. Report neutral or negative results honestly and do not retain speculative optimization code.
- Preserve benchmark coverage in `*_benchmark_test.go` so future changes can reproduce the comparison. Gate important allocation improvements with `testing.AllocsPerRun` where stable.

Suggested invocation:

```sh
go test -run '^$' -bench '<relevant benchmark>' -benchmem -count=5
```

Benchmarks requiring a writable PKCS#11 token must accept configuration through an explicit environment variable such as `CRYPTO11_BENCH_CONFIG` and skip with a clear message when it is absent.

## Correctness and compatibility gates

- Preserve exported names, signatures, interfaces, errors, nil behavior, result ordering, configuration fields, and algorithm selection unless the user explicitly authorizes a breaking change.
- Test both singular and plural lookup semantics when changing object discovery. A singular lookup may limit retrieval to one object; a plural lookup must still return every match.
- Test success, empty/not-found, invalid input, partial failure, and cleanup paths relevant to the change.
- Do not mutate caller-owned slices, maps, attributes, options, or buffers unless the public contract explicitly permits it. Add a regression assertion when ownership is not obvious.
- Run formatting and static checks:

```sh
gofmt -w <changed-go-files>
go vet ./...
git diff --check
```

- Run the full test suite when the configured PKCS#11 test token is available:

```sh
go test ./...
```

If the repository's configured HSM is unavailable, run all token-independent tests plus targeted integration tests against an isolated SoftHSM token. State the limitation; a compile-only result is not a substitute for an integration test.

## Memory safety and ownership gates

Review every changed cgo or PKCS#11 path for these invariants:

- Every successful `FindObjectsInit` has exactly one `FindObjectsFinal`, including error paths.
- Every borrowed session is returned to its pool exactly once. Long-lived HMAC or block-mode operations retain their session until finalization or `Close`, and release it exactly once.
- Every PKCS#11/cgo parameter that exposes `Free` is freed exactly once and only after the last C call that can reference it. Never retain Go pointers in C memory after a call returns.
- Returned buffers do not alias temporary, freed, pooled, or caller-mutable storage unexpectedly.
- Values decoded from token-controlled bytes handle empty, short, oversized, malformed, and architecture-sized input without out-of-bounds reads or unsafe alignment assumptions.
- Sensitive material and cryptographic metadata are not placed in global pools or retained beyond their required lifetime. Avoid adding copies of secrets; where a mutable owned copy is unavoidable, document its lifetime and clear it when doing so is effective and semantically safe.
- Cleanup remains correct on initialization failures, token errors, panics, repeated `Close`, and concurrent shutdown.
- Do not introduce `unsafe` to gain performance without a benchmark demonstrating material production benefit and focused tests covering alignment, length, lifetime, and `checkptr` behavior.

Run race detection for every code change, targeting the full suite when possible:

```sh
go test -race ./...
```

For changes involving `unsafe`, cgo pointer conversion, binary decoding, or buffer arithmetic, also run focused tests with strict pointer checking:

```sh
go test -gcflags=all=-d=checkptr=2 ./...
```

Add fuzz or table-driven tests for parsers and token-controlled byte decoding when malformed input can reach the changed code. Include zero length, one byte, boundary length, one past the boundary, and large input.

## Production-impact requirement

Performance claims must identify:

- the exported API affected;
- why the changed code executes in production;
- the workload where the improvement applies;
- baseline and candidate measurements;
- correctness, compatibility, allocation, and concurrency results;
- environmental limits, especially differences between SoftHSM and a network or hardware HSM.

Do not claim that a microbenchmark improvement will improve production when token latency, network latency, or HSM throughput dominates and the end-to-end benchmark does not show a measurable change.
