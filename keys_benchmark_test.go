package crypto11

import (
	"fmt"
	"os"
	"testing"
)

// BenchmarkFindOne measures the production lookup path against the previous
// implementation, which fetched every matching handle before returning one.
// It requires an isolated writable PKCS#11 token because setup creates keys:
//
//	CRYPTO11_BENCH_CONFIG=/path/to/config go test -run '^$' -bench BenchmarkFindOne -benchmem
func BenchmarkFindOne(b *testing.B) {
	config := os.Getenv("CRYPTO11_BENCH_CONFIG")
	if config == "" {
		b.Skip("CRYPTO11_BENCH_CONFIG is not set")
	}

	ctx, err := ConfigureFromFile(config)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = ctx.Close() })

	const objectCount = 1000
	keys := make([]*SecretKey, 0, objectCount)
	for i := range objectCount {
		key, err := ctx.GenerateSecretKeyWithLabel(
			[]byte(fmt.Sprintf("benchmark-find-one-id-%03d", i)),
			[]byte(fmt.Sprintf("benchmark-find-one-label-%03d", i)),
			128,
			CipherAES,
		)
		if err != nil {
			b.Fatal(err)
		}
		keys = append(keys, key)
	}
	b.Cleanup(func() {
		for _, key := range keys {
			_ = key.Delete()
		}
	})

	attributes := NewAttributeSet()

	b.Run("FirstOnly", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := ctx.FindKeyWithAttributes(attributes)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("FetchAllLegacy", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			keys, err := ctx.FindKeysWithAttributes(attributes)
			if err != nil {
				b.Fatal(err)
			}
			if len(keys) == 0 {
				b.Fatal("no key found")
			}
		}
	})
}
