package crypto11

import "testing"

var (
	benchmarkBytes []byte
	benchmarkUint  uint
)

func BenchmarkCKULongEncoding(b *testing.B) {
	b.Run("CallerBufferZeroAlloc", func(b *testing.B) {
		b.ReportAllocs()
		var dst [8]byte
		for b.Loop() {
			putUlong(dst[:], 0x11223344)
		}
		benchmarkUint = uint(dst[0])
	})

	b.Run("ReturnedSlice", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			benchmarkBytes = ulongToBytes(0x11223344)
		}
	})
}

func BenchmarkCKULongDecoding(b *testing.B) {
	encoded := ulongToBytes(0x11223344)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkUint = bytesToUlong(encoded)
	}
}

func BenchmarkPSSParameterEncoding(b *testing.B) {
	const hash, mgf, saltLength = uint(0x250), uint(0x2), uint(32)

	b.Run("Batched", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			benchmarkBytes = ulongsToBytes(hash, mgf, saltLength)
		}
	})

	b.Run("SeparateLegacy", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			benchmarkBytes = encodeULongsSeparately(hash, mgf, saltLength)
		}
	})
}

// encodeULongsSeparately models the previous RSA-PSS parameter path: three
// independently allocated CK_ULONG values followed by one concatenation.
func encodeULongsSeparately(values ...uint) []byte {
	parts := make([][]byte, len(values))
	total := 0
	for i, value := range values {
		parts[i] = ulongToBytes(value)
		total += len(parts[i])
	}

	result := make([]byte, total)
	offset := 0
	for _, part := range parts {
		offset += copy(result[offset:], part)
	}
	return result
}

func TestCKULongAllocationBudgets(t *testing.T) {
	encoded := ulongToBytes(0x11223344)

	decodeAllocs := testing.AllocsPerRun(1_000, func() {
		benchmarkUint = bytesToUlong(encoded)
	})
	if decodeAllocs != 0 {
		t.Fatalf("bytesToUlong allocated %.2f objects per call; want zero", decodeAllocs)
	}

	callerBufferAllocs := testing.AllocsPerRun(1_000, func() {
		var dst [8]byte
		putUlong(dst[:], 0x11223344)
		benchmarkUint = uint(dst[0])
	})
	if callerBufferAllocs != 0 {
		t.Fatalf("putUlong allocated %.2f objects per call; want zero", callerBufferAllocs)
	}

	batchedAllocs := testing.AllocsPerRun(1_000, func() {
		benchmarkBytes = ulongsToBytes(0x250, 0x2, 32)
	})
	legacyAllocs := testing.AllocsPerRun(1_000, func() {
		benchmarkBytes = encodeULongsSeparately(0x250, 0x2, 32)
	})
	if batchedAllocs > 1 {
		t.Fatalf("ulongsToBytes allocated %.2f objects per call; want at most one", batchedAllocs)
	}
	if batchedAllocs >= legacyAllocs {
		t.Fatalf("batched encoding allocations %.2f; want fewer than legacy %.2f", batchedAllocs, legacyAllocs)
	}
}
