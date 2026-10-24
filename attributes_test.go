// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"encoding/hex"
	"fmt"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeprecatedCkaAliases pins the deprecated Cka* constants to the binding's
// CKA_* values, including the two attribute values the header names twice and
// an array attribute, so code still using them keeps addressing the same
// attributes.
func TestDeprecatedCkaAliases(t *testing.T) {
	assert.Equal(t, uint(pkcs11.CKA_LABEL), CkaLabel)
	assert.Equal(t, uint(pkcs11.CKA_EC_PARAMS), CkaEcdsaParams)
	assert.Equal(t, uint(pkcs11.CKA_EC_PARAMS), CkaEcParams)
	assert.Equal(t, uint(pkcs11.CKA_SUBPRIME_BITS), CkaSubPrimeBits)
	assert.Equal(t, uint(pkcs11.CKA_WRAP_TEMPLATE), CkaWrapTemplate)
	assert.NotZero(t, CkaWrapTemplate&pkcs11.CKF_ARRAY_ATTRIBUTE, "array attributes keep CKF_ARRAY_ATTRIBUTE")
	assert.Equal(t, uint(pkcs11.CKA_DECAPSULATE), CkaDecapsulate)

	a := NewAttributeSet()
	require.NoError(t, a.Set(CkaLabel, []byte("legacy")))
	assert.Equal(t, []byte("legacy"), a[pkcs11.CKA_LABEL].Value, "a deprecated constant and its CKA_ name address the same entry")
}

func TestSetNoPanicOnWrongType(t *testing.T) {
	a := NewAttributeSet()
	err := a.Set(pkcs11.CKA_ID, []string{"this is not allowed"})
	assert.Error(t, err)
}

func TestNewAttributeNoPanicOnWrongType(t *testing.T) {
	_, err := NewAttribute(pkcs11.CKA_ID, []string{"this is not allowed"})
	assert.Error(t, err)
}

func TestAttributeSetStringRedactsKeyMaterial(t *testing.T) {
	secret := []byte("this-is-the-secret-key-material!")
	a := NewAttributeSet()
	require.NoError(t, a.Set(pkcs11.CKA_ID, []byte("public-id")))
	require.NoError(t, a.Set(pkcs11.CKA_LABEL, []byte("my label")))
	require.NoError(t, a.Set(pkcs11.CKA_VALUE, secret))
	require.NoError(t, a.Set(pkcs11.CKA_PRIVATE_EXPONENT, secret))
	require.NoError(t, a.Set(pkcs11.CKA_PRIME_1, secret))
	require.NoError(t, a.Set(pkcs11.CKA_PRIME_2, secret))
	require.NoError(t, a.Set(pkcs11.CKA_EXPONENT_1, secret))
	require.NoError(t, a.Set(pkcs11.CKA_EXPONENT_2, secret))
	require.NoError(t, a.Set(pkcs11.CKA_COEFFICIENT, secret))
	require.NoError(t, a.Set(pkcs11.CKA_SEED, secret))
	require.NoError(t, a.Set(pkcs11.CKA_VENDOR_DEFINED+1, secret))

	for _, rendered := range []string{a.String(), fmt.Sprintf("%v", a), fmt.Sprint(a)} {
		assert.NotContains(t, rendered, hex.EncodeToString(secret), "secret must not appear in hex")
		assert.NotContains(t, rendered, string(secret), "secret must not appear raw")
		assert.Contains(t, rendered, hex.EncodeToString([]byte("public-id")), "non-sensitive attributes still render")
		assert.Contains(t, rendered, "CKA_VALUE: <redacted, 32 bytes>")
	}

	assert.False(t, sensitiveAttribute(pkcs11.CKA_ID))
	assert.False(t, sensitiveAttribute(pkcs11.CKA_MODULUS), "the public modulus is not a secret")
	assert.True(t, sensitiveAttribute(pkcs11.CKA_VALUE))
	assert.True(t, sensitiveAttribute(pkcs11.CKA_SEED), "an ML-KEM/ML-DSA/SLH-DSA seed is the private key")
	assert.True(t, sensitiveAttribute(pkcs11.CKA_VENDOR_DEFINED))
}
