package crypto11

import (
	"fmt"
	"strings"
	"testing"
)

var benchmarkAttributeString string

func BenchmarkAttributeSetString(b *testing.B) {
	for _, size := range []int{32, 1024} {
		b.Run(fmt.Sprintf("Payload%d", size), func(b *testing.B) {
			attributes := AttributeSet{
				CkaLabel: {Type: CkaLabel, Value: []byte(strings.Repeat("a", size))},
				CkaId:    {Type: CkaId, Value: []byte(strings.Repeat("b", 32))},
				CkaValue: {Type: CkaValue, Value: []byte(strings.Repeat("s", size))},
			}
			b.ReportAllocs()
			for b.Loop() {
				benchmarkAttributeString = attributes.String()
			}
		})
	}
}
