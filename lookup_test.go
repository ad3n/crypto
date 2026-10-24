package crypto11

import (
	"fmt"
	"sync"
	"testing"

	pkcs11 "github.com/ad3n/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/require"
)

func TestLookupSharedAttributes(t *testing.T) {
	ctx := testContext(t)
	id := randomBytes()
	key, err := ctx.GenerateSecretKeyWithLabel(id, id, 128, CipherAES)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, key.Delete()) })

	attributes := NewAttributeSet()
	for kind, value := range map[AttributeType]any{
		CkaId: id, CkaLabel: id, CkaKeyType: uint(pkcs11.CKK_AES), CkaToken: true,
	} {
		require.NoError(t, attributes.Set(kind, value))
	}

	original := attributes.Copy()
	var workers sync.WaitGroup
	errors := make(chan error, 4)
	for range 4 {
		workers.Go(func() {
			for range 5 {
				found, err := ctx.FindKeyWithAttributes(attributes)
				if err != nil || found == nil {
					errors <- fmt.Errorf("singular lookup: %v", err)
					return
				}

				all, err := ctx.FindKeysWithAttributes(attributes)
				if err != nil || len(all) != 1 {
					errors <- fmt.Errorf("plural lookup: %v, count %d", err, len(all))
					return
				}
			}

			errors <- nil
		})
	}

	workers.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}

	for _, template := range []AttributeSet{nil, NewAttributeSet()} {
		found, err := ctx.FindKeyWithAttributes(template)
		require.NoError(t, err)
		require.NotNil(t, found)
		all, err := ctx.FindKeysWithAttributes(template)
		require.NoError(t, err)
		containsKey := false
		for _, candidate := range all {
			containsKey = containsKey || candidate.handle == key.handle
		}

		require.True(t, containsKey)
		require.Empty(t, template)
	}

	require.Equal(t, original, attributes)
	require.Zero(t, ctx.PoolStats().InUse)
}

func TestLookupAllocationBudgets(t *testing.T) {
	ctx := testContext(t)
	id := make([]byte, 50)
	copy(id, randomBytes())
	key, err := ctx.GenerateSecretKeyWithLabel(id, id, 128, CipherAES)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, key.Delete()) })

	attributes := NewAttributeSet()
	for kind, value := range map[AttributeType]any{
		CkaId: id, CkaLabel: id, CkaKeyType: uint(pkcs11.CKK_AES), CkaToken: true,
	} {
		require.NoError(t, attributes.Set(kind, value))
	}

	singular := testing.AllocsPerRun(100, func() {
		found, err := ctx.FindKeyWithAttributes(attributes)
		if err != nil || found == nil {
			t.Fatalf("singular: %v", err)
		}
	})
	plural := testing.AllocsPerRun(100, func() {
		found, err := ctx.FindKeysWithAttributes(attributes)
		if err != nil || len(found) != 1 {
			t.Fatalf("plural: %v", err)
		}
	})
	if plural-singular > 6 {
		t.Fatalf("plural overhead = %v allocations; want at most 6 (singular=%v, plural=%v)", plural-singular, singular, plural)
	}
}
