package crypto11

import (
	"fmt"
	"os"
	"testing"

	pkcs11 "github.com/ad3n/pkcs11-go/cryptoki"
)

func BenchmarkLookupAttributes(b *testing.B) {
	config := os.Getenv("CRYPTO11_BENCH_CONFIG")
	if config == "" {
		b.Skip("CRYPTO11_BENCH_CONFIG is not set")
	}

	ctx, err := ConfigureFromFile(config)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := ctx.Close(); err != nil {
			b.Error(err)
		}
	})

	var keys []*SecretKey
	b.Cleanup(func() {
		for _, key := range keys {
			if err := key.Delete(); err != nil {
				b.Error(err)
			}
		}
	})

	for i := range 128 {
		id := []byte(fmt.Sprintf("lookup-attributes-%032d", i))
		key, err := ctx.GenerateSecretKeyWithLabel(id, id, 128, CipherAES)
		if err != nil {
			b.Fatal(err)
		}

		keys = append(keys, key)
	}

	attributes := NewAttributeSet()
	for kind, value := range map[AttributeType]any{
		CkaId:      []byte(fmt.Sprintf("lookup-attributes-%032d", 64)),
		CkaLabel:   []byte(fmt.Sprintf("lookup-attributes-%032d", 64)),
		CkaKeyType: uint(pkcs11.CKK_AES),
		CkaToken:   true,
	} {
		if err := attributes.Set(kind, value); err != nil {
			b.Fatal(err)
		}
	}

	b.Run("Singular", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			key, err := ctx.FindKeyWithAttributes(attributes)
			if err != nil || key == nil {
				b.Fatalf("lookup: %v", err)
			}
		}
	})
	b.Run("Plural", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			keys, err := ctx.FindKeysWithAttributes(attributes)
			if err != nil || len(keys) != 1 {
				b.Fatalf("lookup: %v, count %d", err, len(keys))
			}
		}
	})
}
