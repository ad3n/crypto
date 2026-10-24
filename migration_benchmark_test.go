package crypto11

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"testing"
)

func BenchmarkRSAPSSSign(b *testing.B) {
	config := os.Getenv("CRYPTO11_BENCH_CONFIG")
	if config == "" {
		b.Skip("CRYPTO11_BENCH_CONFIG is not set")
	}

	ctx, err := ConfigureFromFile(config)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = ctx.Close() })

	key, err := ctx.GenerateRSAKeyPair([]byte("benchmark-pss-migration"), 2048)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := key.Delete(); err != nil {
			b.Error(err)
		}
	})

	digest := sha256.Sum256(make([]byte, 1024))
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	signature, err := key.Sign(rand.Reader, digest[:], opts)
	if err != nil {
		b.Fatal(err)
	}

	if err := rsa.VerifyPSS(key.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], signature, opts); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := key.Sign(rand.Reader, digest[:], opts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAttributeSetCopy(b *testing.B) {
	attributes := NewAttributeSet()
	for _, kind := range []AttributeType{CkaId, CkaLabel, CkaValue, CkaApplication} {
		if err := attributes.Set(kind, make([]byte, 64)); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	for b.Loop() {
		copy := attributes.Copy()
		if len(copy) != len(attributes) {
			b.Fatal("incomplete copy")
		}
	}
}
