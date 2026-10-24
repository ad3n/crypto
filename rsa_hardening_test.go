// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every failure of the decryption itself is reported as rsa.ErrDecryption, whatever the token's
// reason, so that the error cannot serve as a padding oracle.
func TestRSADecryptFailuresAreErrDecryption(t *testing.T) {
	ctx := testContext(t)
	key, err := ctx.GenerateRSAKeyPair(randomBytes(), rsaSize)
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	k := rsaSize / 8
	garbage := make([]byte, k)
	_, err = rand.Read(garbage)
	require.NoError(t, err)
	garbage[0] = 0 // below the modulus

	for name, ciphertext := range map[string][]byte{
		"BadPadding": garbage,
		"TooShort":   garbage[:16],
		"TooLong":    append(append([]byte{}, garbage...), 1),
	} {
		t.Run(name, func(t *testing.T) {
			// A token with implicit rejection returns a synthetic plaintext for bad padding instead
			// of failing, which is fine; a failure must still say no more than ErrDecryption.
			if _, err := key.Decrypt(rand.Reader, ciphertext, nil); err != nil {
				assert.Equal(t, rsa.ErrDecryption, err, "PKCS#1 v1.5")
			}
			_, err := key.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA1})
			assert.Equal(t, rsa.ErrDecryption, err, "OAEP")
		})
	}
}

func TestCheckRSASignature(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("message"))

	pkcs1, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	require.NoError(t, err)
	pss, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], nil)
	require.NoError(t, err)
	pssOpts := &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}

	assert.NoError(t, checkRSASignature(&priv.PublicKey, digest[:], pkcs1, crypto.SHA256))
	assert.NoError(t, checkRSASignature(&priv.PublicKey, digest[:], pss, pssOpts))

	// A faulty signature is caught.
	faulty := append([]byte{}, pkcs1...)
	faulty[len(faulty)/2] ^= 1
	assert.Equal(t, errRSASignatureCheck, checkRSASignature(&priv.PublicKey, digest[:], faulty, crypto.SHA256))
	faulty = append([]byte{}, pss...)
	faulty[len(faulty)/2] ^= 1
	assert.Equal(t, errRSASignatureCheck, checkRSASignature(&priv.PublicKey, digest[:], faulty, pssOpts))

	// Without a public key there is nothing to check against.
	assert.NoError(t, checkRSASignature(nil, digest[:], faulty, crypto.SHA256))
}

func TestExportRSAPublicKeyRejectsEvenModulus(t *testing.T) {
	ctx := testContext(t)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	even := &rsa.PublicKey{N: new(big.Int).Lsh(priv.N, 1), E: priv.E}
	handle := plantPublicKey(t, ctx, randomBytes(), randomBytes(), even)
	defer destroyObject(t, ctx, handle)

	require.NoError(t, ctx.withSession(func(session *pkcs11Session) error {
		_, err := exportRSAPublicKey(session, handle)
		assert.ErrorIs(t, err, errMalformedRSAPublicKey)
		return nil
	}))
}
