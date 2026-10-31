package crypto11

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"testing"

	pkcs11 "github.com/ad3n/pkcs11-go/cryptoki"
)

func TestAttributeStringCompatibility(t *testing.T) {
	for _, size := range []int{0, 1, 255, 256, 257, 1024, 65536} {
		for _, kind := range []uint{CkaLabel, CkaValue, pkcs11.CKA_VENDOR_DEFINED, 0x7ffffffe} {
			t.Run(fmt.Sprintf("%x/%d", kind, size), func(t *testing.T) {
				input := bytes.Repeat([]byte{0xab}, size)
				original := bytes.Clone(input)
				attrs := AttributeSet{kind: {Type: kind, Value: input}}
				want := fmt.Sprintf("%s: %x\n", pkcs11.AttributeName(kind), input)
				if sensitiveAttribute(kind) {
					want = fmt.Sprintf("%s: <redacted, %d bytes>\n", pkcs11.AttributeName(kind), size)
				}

				got := attrs.String()
				if got != want || !bytes.Equal(input, original) {
					t.Fatal("format or caller ownership changed")
				}

				clear(input)
				if got != want {
					t.Fatal("returned string aliases caller storage")
				}
			})
		}
	}

	for _, attrs := range []AttributeSet{nil, {}} {
		if attrs.String() != "" {
			t.Fatal("empty attributes must render an empty string")
		}
	}

	attrs := AttributeSet{CkaLabel: {Value: []byte("label")}, CkaValue: {Value: []byte("secret")}}
	lines := strings.Split(strings.TrimSuffix(attrs.String(), "\n"), "\n")
	sort.Strings(lines)
	if strings.Join(lines, "\n") != "CKA_LABEL: 6c6162656c\nCKA_VALUE: <redacted, 6 bytes>" {
		t.Fatalf("unexpected lines: %q", lines)
	}
}

func TestAttributeStringNilAttribute(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("nil attribute must retain panic behavior")
		}
	}()

	_ = (AttributeSet{CkaLabel: nil}).String()
}

func TestAttributeStringAllocationBudget(t *testing.T) {
	attrs := AttributeSet{CkaLabel: {Value: []byte("public label")}}
	if n := testing.AllocsPerRun(1000, func() { benchmarkAttributeString = attrs.String() }); n > 3 {
		t.Fatalf("String allocations = %v; want at most 3", n)
	}

	if n := testing.AllocsPerRun(1000, func() { benchmarkAttributeString = AttributeSet(nil).String() }); n != 0 {
		t.Fatalf("empty String allocations = %v; want zero", n)
	}
}

func TestAttributeStringConcurrent(t *testing.T) {
	attrs := AttributeSet{CkaLabel: {Value: []byte("public")}}
	want := attrs.String()
	for i := range 8 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			for range 100 {
				if attrs.String() != want {
					t.Fatal("concurrent rendering changed output")
				}
			}
		})
	}
}
