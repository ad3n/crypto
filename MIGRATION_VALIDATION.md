> Historical validation of the initial vendored migration. The vendor limitation below is superseded by the direct fork dependency described in NOTICES.md. Old benchmark log files were subsequently removed.

# API v2 migration validation

Validated on 2026-10-24, Apple M3 Pro, darwin/arm64, Go 1.27.3, SoftHSM 2.7, default GOMAXPROCS=12.

Merged upstream `96a94116f7af5be411d70ce4ea9ed0b929e7e788` into local baseline `7c82c7a3aa45794d4bb61e91ee9c5c7c0baebb7d`. The module and internal imports are `github.com/ad3n/crypto/v2`. The v2 API/binding/configuration changes were explicitly authorized. No remote push is part of this change.

## Production paths and retained optimizations

- `Context.FindKey` / `FindKeyWithAttributes` → `findKeyWithAttributes` → `FindObjects(..., 1)`. Stop at the first supported symmetric key, skip unsupported types as v2 requires, and leave plural discovery exhaustive. Templates are owned copies; the caller's attributes are unchanged. Every successful search initialization registers one deferred finalization. Errors from finalization propagate; failed initialization does not finalize another operation. `withSession` returns or discards the session exactly once.
- `FindKeys` and asymmetric discovery retain preallocated search templates. `AttributeSet.Copy` retains map capacity, and `ToSlice` retains slice capacity and deep-copy ownership.
- `Signer.Sign` with RSA-PSS → typed `pkcs11.NewPSSParams` → binding C marshalling. This replaces the old local batched raw encoder with a single typed parameter allocation; no three-slice concatenation returns. The binding allocates/frees the C parameter around the call. Typed parameters retain upstream mechanism-policy validation. The obsolete local helper and its test-only comparison were removed, not described as a production optimization. A full RSA-PSS signing benchmark and a one-allocation constructor gate cover the replacement.
- Attribute/HMAC ULONG encoding → binding `ckULong`: one owned allocation, native-endian writes, overflow rejection retained. Token-controlled ULONG decoding uses the binding's bounded stack buffer, with zero allocations and no unsafe reinterpretation. No global secret pool was introduced; benchmark sinks contain only fixed public test values.
- Private implementation layouts (`genericAead`, `pkcs11PrivateKey`, `hmacImplementation`, `blockModeCloser`) retain pointer grouping. The block-mode finalizer remains typed. Upstream Context synchronization and the v2 public Config layout were retained instead of mechanically copying old layouts into new types.
- Every session-backed API → `Context.getSession` → `ResourcePool.Get` → `takeIdle`. Profiling the initial v2 candidate found about 89,760 bytes and 11 allocations per serial session acquisition in the list of empty wrappers. Empty wrappers contain no resource; their timestamps are unused. Counting and restoring empty slots removes that allocation while retaining bounded search, capacity, resource ownership, idle preference, and shutdown behavior. No resource or secret is pooled globally. Dedicated serial/contention benchmarks cover this path, and signing/lookup measurements confirm the production effect.

## Measurements

Each row reports the median of five samples. `benchstat` was unavailable, so no statistical significance is claimed; every sample is committed under `validation/`. Default benchmark duration was 1 second. Baseline and candidate ran sequentially on the same machine, toolchain, SoftHSM module, and isolated token, with no validation workloads running concurrently. Binding and implementation changes are the subjects of the comparison.

Lookup setup creates and deletes 1,000 AES-128 keys. Cleanup is registered before generation so partial setup also deletes created keys. RSA-PSS uses a 2048-bit key and SHA-256 digest of a 1 KiB message; generated keys are deleted. Configuration leaves MaxSessions at the same default (1024). Pool-specific benchmarks use capacity 1024 and exercise both serial and contended Get/Put; the contended case uses Go's RunParallel API, while serial benchmarks use b.Loop.

| Benchmark | Before ns/op | Before B/op | Before allocs/op | After ns/op | After B/op | After allocs/op |
|---|---:|---:|---:|---:|---:|---:|
| CKULongEncoding/ReturnedSlice | 6.058 | 8 | 1 | 6.245 | 8 | 1 |
| CKULongDecoding | 1.807 | 0 | 0 | 1.863 | 0 | 0 |
| FindOne/FirstOnly | 2.31518e+07 | 304 | 18 | 2.44768e+07 | 304 | 17 |
| FindOne/FetchAllLegacy | 7.96144e+07 | 214393 | 8226 | 7.98162e+07 | 183033 | 7230 |
| RSAPSSSign | 682327 | 365 | 8 | 725388 | 1792 | 26 |
| AttributeSetCopy | 148.2 | 384 | 8 | 151.1 | 384 | 8 |
| IdleReuse/Serial (upstream v2 → patched v2) | 29206 | 89760 | 11 | 23584 | 0 | 0 |
| IdleReuse/Contended (upstream v2 → patched v2) | 5532 | 6898 | 6 | 2152 | 0 | 0 |

The first six rows compare optimized local v1 with the final v2 candidate. The last two compare upstream v2 pool code against the pool correction, using the identical benchmark file. `FetchAllLegacy` calls the public plural lookup; it is a workload comparator, not a claim that plural discovery can be removed.

The singular lookup remains much cheaper than exhaustive lookup, with 17 vs 7,230 allocations. Relative to local v1, singular median time increased about 5.7%, while allocations dropped from 18 to 17. Plural time was effectively neutral; memory and allocations improved. ULONG allocation budgets are unchanged; small timing differences should not be treated as production throughput changes.

RSA-PSS is **not faster than local v1**: median time increased about 6.3%, and allocations increased from 8 / 365 bytes to 26 / 1,792 bytes. V2 verifies the returned RSA signature to mitigate faulty RSA-CRT output, and the new binding adds its own ownership/policy work. Those safety checks are retained. Parameter construction itself remains at most one allocation. The initial v2 candidate was 91,552 bytes / 37 allocations per signing operation; removing the pool regression reduces it to 1,792 / 26. See `validation/candidate.txt` for the initial five samples. No claim is made that these SoftHSM results predict network or hardware HSM throughput.

## Correctness, race, static and memory-safety evidence

The full verbose suite passed with 594 passing test/subtest lines and 14 skips. New regression coverage includes singular/plural lookup cardinality, caller attribute ownership, empty and invalid requests, failed initialization/session recovery, pool accounting, attribute deep copies, decoder lengths 0/1/width−1/width/width+1/4096, and stable allocation budgets. Upstream tests cover poisoned sessions, close while operations are in flight, factory failure, pool shrinking/closing, key-pair matching, RSA hardening, AEAD, HMAC and block-mode cleanup.

Executed successfully (commands shown without output redirection):

```sh
gofmt -w *.go
gofmt -w common_benchmark_test.go internal/pool/resource_pool.go internal/pool/reuse_benchmark_test.go vendor/github.com/eclipse-keypont/pkcs11-go/cryptoki/marshal.go
PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so go test -v ./...
PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so go test -race ./...
PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so go test -gcflags=all=-d=checkptr=2 ./...
PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so go test -race -gcflags=all=-d=checkptr=2 -run 'TestMigrated|TestCKULongAllocationBudgets|TestIdleReuse' ./...
go vet ./...
git diff --check
git diff --cached --check
git apply --reverse --check patches/pkcs11-go-rc4.patch
cc -fsanitize=address,undefined -Ivendor/github.com/eclipse-keypont/pkcs11-go/cryptoki -Ivendor/github.com/eclipse-keypont/pkcs11-go/internal/headers testdata/memzero.c vendor/github.com/eclipse-keypont/pkcs11-go/cryptoki/shim.c -o /private/tmp/crypto-v2-validation/memzero
/private/tmp/crypto-v2-validation/memzero
```

The C test checks actual vendored `ck_memzero` with nil, zero, one-byte, boundary, and large buffers, including untouched guard bytes. AddressSanitizer and UBSan reported no errors. The final combined targeted run also covered the last-added PSS allocation assertion.

`betteralign ./...` and `betteralign -apply ./...` ran. The final check returns exit 3 with intentionally retained diagnostics: ResourcePool, Timer and Context (concurrency layout/out-of-scope refactoring), Config (public field order), pkcs11Object and rawCurve (positional literals), and encapsulationPair/pubCandidate (unrelated upstream implementations). Automatic rewrites outside the reviewed private-layout scope were reverted. This is **not** a clean betteralign result. Early sandboxed tool invocations could not resolve packages and were rerun successfully with filesystem permission.

Initial upstream compilation failed because its Apple branch called unavailable `explicit_bzero`. An initial regression test expected explicit finalization after `CKR_OPERATION_ACTIVE`; upstream correctly discards that poisoned session, so the test was corrected to assert successful recovery instead. Both issues were resolved before final gates. The linker emits an existing duplicate nwrfcsdk rpath warning; tests still link and pass.

## Reproduce benchmarks

The baseline tree was extracted with `git archive` at `7c82c7a`, and `migration_benchmark_test.go` was copied into it. The upstream pool tree was extracted at `96a9411`, with the same `reuse_benchmark_test.go` and module files copied in. Benchmark commands executed:

```sh
SOFTHSM2_CONF=/private/tmp/crypto-v2-validation/softhsm.conf CRYPTO11_BENCH_CONFIG=/private/tmp/crypto-v2-validation/config.json go test -C /private/tmp/crypto-v2-validation/baseline -run '^$' -bench 'Benchmark(FindOne|CKULong|RSAPSSSign|AttributeSetCopy)' -benchmem -count=5
SOFTHSM2_CONF=/private/tmp/crypto-v2-validation/softhsm.conf CRYPTO11_PROVISION=0 PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so PKCS11_TOKEN_LABEL=crypto-v2-bench PKCS11_PIN=1234 CRYPTO11_BENCH_CONFIG=/private/tmp/crypto-v2-validation/config.json go test -run '^$' -bench 'Benchmark(FindOne|CKULong|RSAPSSSign|AttributeSetCopy)' -benchmem -count=5
go test -C /private/tmp/crypto-v2-validation/upstream-pool -run '^$' -bench BenchmarkIdleReuse -benchmem -count=5 ./internal/pool
go test -run '^$' -bench BenchmarkIdleReuse -benchmem -count=5 ./internal/pool
```

All four commands passed. Profiling used the same isolated token with `go test -run '^$' -bench '^BenchmarkRSAPSSSign$' -benchmem -memprofile /private/tmp/crypto-v2-validation/mem.pprof -o /private/tmp/crypto-v2-validation/profile.test`, followed by `go tool pprof -top -alloc_space /private/tmp/crypto-v2-validation/profile.test /private/tmp/crypto-v2-validation/mem.pprof`.

`softhsm.conf` points only to `/private/tmp/crypto-v2-validation/tokens`; `config.json` is mode 0600 and selects label `crypto-v2-bench`, module `/opt/homebrew/lib/softhsm/libsofthsm2.so`, and disposable test PIN `1234`. No production token was accessed. New HSM benchmarks skip explicitly without `CRYPTO11_BENCH_CONFIG`. The full suite uses upstream's temporary-token provisioning and automatic teardown, not the benchmark token.

## Limits and dependency patch

The repository's previous `/usr/lib/softhsm/libsofthsm2.so` configuration is not available on this macOS host. Validation instead used an isolated Homebrew SoftHSM token. ML-KEM, HMAC GENERAL, most OAEP variants, and the no-login scenario were skipped according to module capabilities/test prerequisites. Real hardware/network HSMs, SoftHSMv3 PQC, other operating systems and 32-bit ABI execution were not available. These are explicit coverage limits, not passing integration tests.

The vendor patch is necessary for macOS compilation and retained ULONG encoding allocations. See `NOTICES.md` and `patches/pkcs11-go-rc4.patch`. Re-vendoring must reapply it. A downstream Go module does not inherit this checkout's vendor directory; external consumers need a fixed binding release/fork before these local dependency fixes propagate. This task merges and validates the local checkout only.

Patch context and unmodified third-party source retain their original whitespace via `.gitattributes`; the vendored spew README uses a seven-character underline, not a conflict marker. An upstream workflow trailing blank line was removed. These metadata-only adjustments do not affect runtime benchmarks.
