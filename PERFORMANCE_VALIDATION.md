# Lookup allocation validation — 2026-10-24

Baseline: `bacb625`. Candidate changes only symmetric lookup template preparation in production. Public API output from `go doc -all .` is identical before and after. No dependency, exported signature, error, algorithm, result ordering contract, configuration field or minimum Go version changes.

## Production path and ownership

`Context.FindKeys`, `FindAllKeys`, and `FindKeysWithAttributes` use `FindKeysWithAttributes`. It already deep-copies caller attributes before adding CKA_CLASS. The candidate constructs the pointer slice from that private copy instead of deep-copying it a second time. The Copy and Set operations themselves are unchanged, including nil handling, rekeying by attribute Type, and class validation. The private map and slice live only for the synchronous lookup; binding marshalling owns its C copies.

`Context.FindKey` and `FindKeyWithAttributes` use `findKeyWithAttributes`. The candidate reserves one extra pointer slot for CKA_CLASS while still cloning every input attribute. This reduces the backing array's size; Go 1.27.3 already optimizes part of the original allocation, so the allocation count is unchanged.

Search initialization/finalization, errors, session return/discard, handle retrieval and result construction are untouched. Singular search still stops at the first supported key; plural search still returns every supported match. No secret pool, unsafe conversion, added secret copy, or changed C lifetime is introduced. Existing caller-owned buffers remain independent.

A fully zero-allocation lookup would conflict with the existing owned-result and cgo paths. This change does not remove those required allocations. Existing zero-allocation decoder and session-reuse regression gates still pass.

## Go version

Development toolchain and `.go-version` already pin Go 1.27.3. All setup-go workflow inputs now read `.go-version` explicitly. The minimum `go 1.25.0` directive is intentionally retained: raising it would break older consumers, contrary to the compatibility requirement. New concurrent tests use sync.WaitGroup.Go, available at the supported minimum. No API requiring a newer language version was introduced into production code.

## Benchmark evidence

Apple M3 Pro, darwin/arm64, Go 1.27.3, SoftHSM 2.7, GOMAXPROCS default 12, default one-second benchmark duration. Same machine, module, isolated configuration and token were used throughout. No production token was accessed. Two five-sample rounds per side ran sequentially in before/after then after/before order; the second round checked initial timing variation. No validation workloads ran concurrently with measurement. Benchmark setup registers cleanup before generating objects.

`BenchmarkFindOne` uses 1,000 AES-128 objects and an empty search template. `BenchmarkLookupAttributes` uses 128 AES-128 objects and a four-attribute template (ID, label, key type and token flag), matching one key. Both call the exported API, use b.Loop and ReportAllocs, and require CRYPTO11_BENCH_CONFIG.

Medians across ten samples:

| Benchmark | Before ns/op | After ns/op | Before B/op | After B/op | Before allocs/op | After allocs/op |
|---|---:|---:|---:|---:|---:|---:|
| FindOne/FirstOnly | 2.40802e+07 | 2.37256e+07 | 304 | 304 | 17 | 17 |
| FindOne/FetchAllLegacy | 7.86236e+07 | 7.9744e+07 | 183033 | 182993 | 7230 | 7228 |
| LookupAttributes/Singular | 3.30757e+06 | 3.30574e+06 | 704 | 688 | 26 | 26 |
| LookupAttributes/Plural | 3.34357e+06 | 3.33691e+06 | 1360 | 1048 | 42 | 32 |

Four-attribute plural lookup saves 312 bytes (22.9%) and 10 allocations (23.8%). Singular lookup saves 16 bytes with unchanged allocations. Bulk plural lookup saves two allocations and about 40 bytes. Timing is approximately neutral: the bulk plural median is 1.4% higher, within the observed run variation; no throughput improvement or statistical significance is claimed. Benchstat was unavailable, so every sample appears below. Hardware/network HSM latency may dominate these local allocation savings.

## Tests and exact commands

Passed:

```sh
gofmt -w keys.go lookup_benchmark_test.go lookup_test.go
PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so go test -v ./...
PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so go test -race ./...
PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so go test -gcflags=all=-d=checkptr=2 ./...
PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so go test -race -gcflags=all=-d=checkptr=2 -run 'TestLookup|TestMigratedLookup' ./...
go vet ./...
git diff --check
sh -n scripts/check-consumer.sh
go doc -all . > /private/tmp/crypto-lookup-perf/api-after.txt
go -C /private/tmp/crypto-lookup-perf/baseline doc -all . > /private/tmp/crypto-lookup-perf/api-before.txt
diff -u /private/tmp/crypto-lookup-perf/api-before.txt /private/tmp/crypto-lookup-perf/api-after.txt
```

New regression tests cover concurrent reuse of caller attributes, unchanged maps/buffers, nil and empty templates, singular/plural discovery and balanced sessions. Existing tests cover invalid class, not-found, failed initialization/recovery, plural cardinality and deep-copy ownership. The allocation gate compares plural overhead against singular for the same four-attribute workload; the limit is six allocations. It rejects the baseline's 16-allocation overhead. Initial absolute budgets were corrected after measurement: singular remains at 26 allocations, and checkptr instrumentation adds five allocations to each operation. The relative gate passes both normal and instrumented builds without skipping the safety checks. The final targeted command reruns the updated gate and added nil/empty cases under both race and checkptr.

`betteralign ./...`, `betteralign -apply ./...`, and the final `betteralign ./...` were run. The eight pre-existing diagnostics remain deliberately unresolved: ResourcePool/Timer/Context concurrency layout, public Config ordering, positional pkcs11Object/rawCurve literals, and unrelated ML-KEM/pairing types. Automatic out-of-scope changes were restored. Exit 3 is a diagnostic result, not a clean pass.

Workflow references were checked against `.go-version` and go.mod's toolchain; all select 1.27.3. Hosted GitHub Actions were not run locally. Metadata/documentation changes need no runtime benchmark; the production lookup changes are measured above.

The old configured HSM path is unavailable on this Mac. Full suites instead use automatically provisioned isolated SoftHSM tokens. Existing capability skips remain for PQC and unsupported OAEP/HMAC variants; hardware/network HSMs and other ABIs were not available. The existing duplicate rpath linker warning is unchanged.

Benchmark command, run twice in each tree (baseline adds `-C /private/tmp/crypto-lookup-perf/baseline` before `-run`):

```sh
SOFTHSM2_CONF=/private/tmp/crypto-v2-validation/softhsm.conf CRYPTO11_PROVISION=0 PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so CRYPTO11_BENCH_CONFIG=/private/tmp/crypto-v2-validation/config.json go test -run '^$' -bench 'BenchmarkLookupAttributes|BenchmarkFindOne' -benchmem -count=5
```

The baseline was extracted with `git archive HEAD` before production edits were committed and received the identical new lookup benchmark. All four benchmark commands passed. Each sample below is ns/op / B/op / allocs/op, in measured order:

| Benchmark | Before (10 samples) | After (10 samples) |
|---|---|---|
| FindOne/FirstOnly | 23990630 / 304 / 17; 24891704 / 304 / 17; 24169852 / 304 / 17; 23443106 / 304 / 17; 23382792 / 304 / 17; 23979251 / 304 / 17; 23864326 / 304 / 17; 25249412 / 304 / 17; 25238025 / 304 / 17; 25736983 / 304 / 17 | 23388719 / 304 / 17; 23175803 / 304 / 17; 24997067 / 304 / 17; 24079562 / 304 / 17; 23360841 / 304 / 17; 24560820 / 304 / 17; 23775322 / 304 / 17; 23462319 / 304 / 17; 24486324 / 304 / 17; 23675932 / 304 / 17 |
| FindOne/FetchAllLegacy | 78020271 / 183032 / 7230; 78443347 / 183033 / 7230; 77960292 / 183033 / 7230; 78155419 / 183033 / 7230; 78315961 / 183033 / 7230; 81416485 / 183033 / 7230; 80807170 / 183033 / 7230; 82020984 / 183033 / 7230; 79740185 / 183033 / 7230; 78803926 / 183032 / 7230 | 78010866 / 182993 / 7228; 80531214 / 182993 / 7228; 84927837 / 182993 / 7228; 81563357 / 182993 / 7228; 80937158 / 182992 / 7228; 77485554 / 182993 / 7228; 79590188 / 182993 / 7228; 79897729 / 182992 / 7228; 77465917 / 182993 / 7228; 77524432 / 182992 / 7228 |
| LookupAttributes/Singular | 3316819 / 704 / 26; 3284104 / 704 / 26; 3314406 / 704 / 26; 3300726 / 704 / 26; 3382737 / 704 / 26; 3276181 / 704 / 26; 3267403 / 704 / 26; 3375232 / 704 / 26; 3329723 / 704 / 26; 3254435 / 704 / 26 | 3197620 / 688 / 26; 3171247 / 688 / 26; 3151405 / 688 / 26; 3294829 / 688 / 26; 3401746 / 688 / 26; 3241887 / 688 / 26; 3316642 / 688 / 26; 3436311 / 688 / 26; 3399918 / 688 / 26; 3482526 / 688 / 26 |
| LookupAttributes/Plural | 3367767 / 1360 / 42; 3236435 / 1360 / 42; 3214138 / 1360 / 42; 3227684 / 1360 / 42; 3319365 / 1360 / 42; 3229308 / 1360 / 42; 3406467 / 1360 / 42; 3376829 / 1360 / 42; 3386063 / 1360 / 42; 3594863 / 1360 / 42 | 3374901 / 1048 / 32; 3451633 / 1048 / 32; 3437043 / 1048 / 32; 3298916 / 1048 / 32; 3435500 / 1048 / 32; 3419000 / 1048 / 32; 3277750 / 1048 / 32; 3259808 / 1048 / 32; 3260662 / 1048 / 32; 3293896 / 1048 / 32 |
