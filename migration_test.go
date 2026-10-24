package crypto11

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	pkcs11 "github.com/ad3n/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/require"
)

func TestMigratedLookupOwnershipAndCleanup(t *testing.T) {
	ctx := testContext(t)
	label := randomBytes()
	for i := range 3 {
		key, err := ctx.GenerateSecretKeyWithLabel([]byte(fmt.Sprintf("migration-%x-%d", label, i)), label, 128, CipherAES)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, key.Delete()) })
	}

	attributes := NewAttributeSet()
	require.NoError(t, attributes.Set(CkaLabel, label))
	original := attributes.Copy()
	for range 3 {
		key, err := ctx.FindKeyWithAttributes(attributes)
		require.NoError(t, err)
		require.NotNil(t, key)
		all, err := ctx.FindKeysWithAttributes(attributes)
		require.NoError(t, err)
		require.Len(t, all, 3)
		require.Equal(t, original, attributes)
		require.Zero(t, ctx.PoolStats().InUse)
	}

	missing := NewAttributeSet()
	require.NoError(t, missing.Set(CkaLabel, randomBytes()))
	key, err := ctx.FindKeyWithAttributes(missing)
	require.Error(t, err)
	require.Nil(t, key)
	all, err := ctx.FindKeysWithAttributes(missing)
	require.NoError(t, err)
	require.Empty(t, all)

	invalid := attributes.Copy()
	require.NoError(t, invalid.Set(CkaClass, pkcs11.CKO_SECRET_KEY))
	_, err = ctx.FindKeyWithAttributes(invalid)
	require.Error(t, err)
	require.Zero(t, ctx.PoolStats().InUse)

	require.NoError(t, ctx.withSession(func(session *pkcs11Session) error {
		return session.ctx.FindObjectsInit(session.handle, nil)
	}))
	_, err = ctx.FindKeyWithAttributes(attributes)
	require.Error(t, err)
	_, err = ctx.FindKeyWithAttributes(attributes)
	require.NoError(t, err)
	require.Equal(t, original, attributes)
	require.Zero(t, ctx.PoolStats().InUse)
}

func TestMigratedAttributeCopies(t *testing.T) {
	attributes := NewAttributeSet()
	require.NoError(t, attributes.Set(CkaLabel, []byte("owned")))
	copy := attributes.Copy()
	slice := attributes.ToSlice()
	copy[CkaLabel].Value[0] = 'X'
	slice[0].Value[0] = 'Y'
	require.Equal(t, []byte("owned"), attributes[CkaLabel].Value)
}

func TestMigratedULongBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, pkcs11.ULongSize - 1, pkcs11.ULongSize, pkcs11.ULongSize + 1, 4096} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			input := bytes.Repeat([]byte{0xa5}, size)
			original := bytes.Clone(input)
			var padded [8]byte
			copy(padded[:pkcs11.ULongSize], input)
			want := uint(binary.NativeEndian.Uint64(padded[:]))
			if pkcs11.ULongSize == 4 {
				want = uint(binary.NativeEndian.Uint32(padded[:4]))
			}

			require.Equal(t, want, pkcs11.BytesToULong(input))
			require.Equal(t, original, input)
		})
	}
}
