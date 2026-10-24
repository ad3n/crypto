package crypto11

import (
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

var (
	benchmarkBytes  []byte
	benchmarkUint   uint
	benchmarkParams pkcs11.MechanismParams
)

func BenchmarkCKULongEncoding(b *testing.B) {
	b.Run("ReturnedSlice", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			benchmarkBytes = pkcs11.ULongToBytes(0x11223344)
		}
	})
}

func BenchmarkCKULongDecoding(b *testing.B) {
	encoded := pkcs11.ULongToBytes(0x11223344)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkUint = pkcs11.BytesToULong(encoded)
	}
}

func TestCKULongAllocationBudgets(t *testing.T) {
	if n := testing.AllocsPerRun(1000, func() { benchmarkParams = pkcs11.NewPSSParams(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32) }); n > 1 {
		t.Fatalf("PSS parameter allocations = %v; want at most 1", n)
	}

	encoded := pkcs11.ULongToBytes(0x11223344)
	if n := testing.AllocsPerRun(1000, func() { benchmarkBytes = pkcs11.ULongToBytes(0x11223344) }); n > 1 {
		t.Fatalf("encode allocations = %v; want at most 1", n)
	}

	if n := testing.AllocsPerRun(1000, func() { benchmarkUint = pkcs11.BytesToULong(encoded) }); n != 0 {
		t.Fatalf("decode allocations = %v; want 0", n)
	}
}
