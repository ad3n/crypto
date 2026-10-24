package pool

import (
	"context"
	"testing"
)

type reuseResource struct{}

func (*reuseResource) Close() {}

func BenchmarkIdleReuse(b *testing.B) {
	for _, concurrent := range []bool{false, true} {
		name := "Serial"
		if concurrent {
			name = "Contended"
		}

		b.Run(name, func(b *testing.B) {
			p := NewResourcePool(func() (Resource, error) { return &reuseResource{}, nil }, 1024, 1024, 0, 0)
			b.Cleanup(p.Close)
			ctx := context.Background()
			b.ReportAllocs()
			if concurrent {
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						r, err := p.Get(ctx)
						if err != nil {
							b.Error(err)
							return
						}

						p.Put(r)
					}
				})
				return
			}

			for b.Loop() {
				r, err := p.Get(ctx)
				if err != nil {
					b.Fatal(err)
				}

				p.Put(r)
			}
		})
	}
}

func TestIdleReuseAllocationBudget(t *testing.T) {
	p := NewResourcePool(func() (Resource, error) { return &reuseResource{}, nil }, 1024, 1024, 0, 0)
	defer p.Close()

	ctx := context.Background()
	n := testing.AllocsPerRun(100, func() {
		r, err := p.Get(ctx)
		if err != nil {
			t.Fatal(err)
		}

		p.Put(r)
	})
	if n != 0 {
		t.Fatalf("Get/Put allocations = %v; want zero", n)
	}

	if p.Active() != 1 || p.Available() != 1024 || p.InUse() != 0 {
		t.Fatalf("resource accounting changed: %s", p.StatsJSON())
	}
}
