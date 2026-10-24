// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectPublicHalf(t *testing.T) {
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	a, b := &keyA.PublicKey, &keyB.PublicKey

	cand := func(key crypto.PublicKey, match pairMatch) *pubCandidate {
		return &pubCandidate{key: key, match: match}
	}

	t.Run("VerifiedWinsOverEarlierTiers", func(t *testing.T) {
		want := cand(a, pairVerified)
		got, err := selectPublicHalf([]*pubCandidate{cand(b, pairUnverified)}, nil, []*pubCandidate{want})
		require.NoError(t, err)
		assert.Same(t, want, got)
	})
	t.Run("MismatchIsNeverChosen", func(t *testing.T) {
		_, err := selectPublicHalf([]*pubCandidate{cand(b, pairMismatch)}, []*pubCandidate{cand(b, pairMismatch)})
		assert.ErrorIs(t, err, errNoPublicHalf)
	})
	t.Run("AgreeingUnverifiedAccepted", func(t *testing.T) {
		first := cand(a, pairUnverified)
		got, err := selectPublicHalf([]*pubCandidate{first, cand(&ecdsa.PublicKey{Curve: a.Curve, X: a.X, Y: a.Y}, pairUnverified)})
		require.NoError(t, err)
		assert.Same(t, first, got)
	})
	t.Run("DisagreeingUnverifiedRejected", func(t *testing.T) {
		_, err := selectPublicHalf([]*pubCandidate{cand(a, pairUnverified), cand(b, pairUnverified)})
		assert.ErrorIs(t, err, errAmbiguousPublicHalf)
		assert.ErrorIs(t, err, errNoPublicHalf, "callers that skip keys without a public half skip these too")
	})
	t.Run("FirstTierWithUnverifiedDecides", func(t *testing.T) {
		first := cand(a, pairUnverified)
		got, err := selectPublicHalf([]*pubCandidate{cand(b, pairMismatch)}, []*pubCandidate{first}, []*pubCandidate{cand(b, pairUnverified)})
		require.NoError(t, err)
		assert.Same(t, first, got)
	})
	t.Run("Empty", func(t *testing.T) {
		_, err := selectPublicHalf(nil, nil)
		assert.ErrorIs(t, err, errNoPublicHalf)
	})
}

func TestSPKIPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	ecdhKey, err := key.PublicKey.ECDH()
	require.NoError(t, err)

	got, err := spkiPublicKey(der)
	require.NoError(t, err)
	assert.Equal(t, ecdhKey.Bytes(), got)

	_, err = spkiPublicKey(append(der, 0))
	assert.Error(t, err, "trailing data")
}

// plantPublicKey creates a public key object carrying id and label for pub, as any session on
// the token can, logged in or not. It returns the object's handle.
func plantPublicKey(t *testing.T, ctx *Context, id, label []byte, pub crypto.PublicKey) pkcs11.ObjectHandle {
	t.Helper()
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		template = append(template,
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, k.N.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(k.E)).Bytes()))
	case *ecdsa.PublicKey:
		params, err := marshalEcParams(k.Curve)
		require.NoError(t, err)
		ecdhKey, err := k.ECDH()
		require.NoError(t, err)
		point, err := asn1.Marshal(ecdhKey.Bytes())
		require.NoError(t, err)
		template = append(template,
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, params),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, point))
	case ed25519.PublicKey:
		point, err := asn1.Marshal([]byte(k))
		require.NoError(t, err)
		template = append(template,
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC_EDWARDS),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed25519OID),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, point))
	default:
		t.Fatalf("cannot plant a %T", pub)
	}
	var handle pkcs11.ObjectHandle
	require.NoError(t, ctx.withSession(func(session *pkcs11Session) (err error) {
		handle, err = session.ctx.CreateObject(session.handle, template)
		return err
	}))
	return handle
}

func destroyObject(t *testing.T, ctx *Context, handle pkcs11.ObjectHandle) {
	t.Helper()
	assert.NoError(t, ctx.withSession(func(session *pkcs11Session) error {
		return session.ctx.DestroyObject(session.handle, handle)
	}))
}

// pairingCase generates a key pair on the token and a software key of the same type.
type pairingCase struct {
	name     string
	mech     uint
	generate func(ctx *Context, id, label []byte) (Signer, error)
	other    func() (crypto.PublicKey, error)
}

var pairingCases = []pairingCase{
	{
		name: "RSA", mech: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN,
		generate: func(ctx *Context, id, label []byte) (Signer, error) {
			return ctx.GenerateRSAKeyPairWithLabel(id, label, rsaSize)
		},
		other: func() (crypto.PublicKey, error) {
			k, err := rsa.GenerateKey(rand.Reader, rsaSize)
			if err != nil {
				return nil, err
			}
			return &k.PublicKey, nil
		},
	},
	{
		name: "ECDSA", mech: pkcs11.CKM_EC_KEY_PAIR_GEN,
		generate: func(ctx *Context, id, label []byte) (Signer, error) {
			return ctx.GenerateECDSAKeyPairWithLabel(id, label, elliptic.P256())
		},
		other: func() (crypto.PublicKey, error) {
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, err
			}
			return &k.PublicKey, nil
		},
	},
	{
		name: "Ed25519", mech: pkcs11.CKM_EC_EDWARDS_KEY_PAIR_GEN,
		generate: func(ctx *Context, id, label []byte) (Signer, error) {
			return ctx.GenerateEd25519KeyPairWithLabel(id, label)
		},
		other: func() (crypto.PublicKey, error) {
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			return pub, err
		},
	},
}

// keyPairHandles returns the private and public key object handles of a generated key pair.
func keyPairHandles(t *testing.T, key Signer) (priv, pub pkcs11.ObjectHandle) {
	t.Helper()
	switch k := key.(type) {
	case *pkcs11PrivateKeyRSA:
		return k.handle, k.pubKeyHandle
	case *pkcs11PrivateKeyECDSA:
		return k.handle, k.pubKeyHandle
	case *pkcs11PrivateKeyEd25519:
		return k.handle, k.pubKeyHandle
	}
	t.Fatalf("no key handles on %T", key)
	return 0, 0
}

// TestFindKeyPairRejectsPlantedPublicKey plants a public key object that carries a key pair's
// CKA_ID and CKA_LABEL but another key. The lookup must return the genuine public key, and must
// not fall back to the planted one once the genuine object is gone.
func TestFindKeyPairRejectsPlantedPublicKey(t *testing.T) {
	ctx := testContext(t)
	for _, tc := range pairingCases {
		t.Run(tc.name, func(t *testing.T) {
			skipIfMechUnsupported(t, ctx, tc.mech)
			id, label := randomBytes(), randomBytes()
			key, err := tc.generate(ctx, id, label)
			require.NoError(t, err)
			privHandle, pubHandle := keyPairHandles(t, key)
			genuine := key.Public()

			other, err := tc.other()
			require.NoError(t, err)
			planted := make([]pkcs11.ObjectHandle, 3)
			for i := range planted {
				planted[i] = plantPublicKey(t, ctx, id, label, other)
			}
			defer func() {
				for _, h := range planted {
					destroyObject(t, ctx, h)
				}
			}()

			for range 3 {
				found, err := ctx.FindKeyPair(id, label)
				require.NoError(t, err)
				assert.True(t, publicKeysEqual(genuine, found.Public()), "FindKeyPair returned the planted public key")
			}

			// With the genuine public key object gone, only planted ones are left. They must not
			// be taken for the key pair's public half.
			destroyObject(t, ctx, pubHandle)
			defer destroyObject(t, ctx, privHandle)
			_, err = ctx.FindKeyPair(id, label)
			assert.Error(t, err, "a planted public key was accepted once the genuine one was gone")
		})
	}
}

// TestPairedCertificateMustCertifyTheKey imports certificates carrying a key pair's CKA_ID. Only
// one that certifies the key pair's public key may be paired with it, and a key pair whose only
// public half is a certificate must not be built from a certificate for another key.
func TestPairedCertificateMustCertifyTheKey(t *testing.T) {
	skipTest(t, skipTestCert)
	ctx := testContext(t)
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_EC_KEY_PAIR_GEN)

	id := randomBytes()
	key, err := ctx.GenerateECDSAKeyPair(id, elliptic.P256())
	require.NoError(t, err)
	keyHandle := key.(*pkcs11PrivateKeyECDSA).handle

	issuer := generateCertChain(t, "pairing-issuer")[0]
	certFor := func(pub *ecdsa.PublicKey) *x509.Certificate {
		template := certTemplate(t, "pairing-leaf", false)
		template.AuthorityKeyId = issuer.cert.SubjectKeyId
		return createCert(t, template, issuer.cert, pub, issuer.key)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	foreign := certFor(&other.PublicKey)
	own := certFor(key.Public().(*ecdsa.PublicKey))

	require.NoError(t, ctx.ImportCertificate(id, foreign))
	defer func() { _ = ctx.DeleteCertificate(id, nil, foreign.SerialNumber) }()

	leafFor := func() *x509.Certificate {
		paired, err := ctx.FindAllPairedCertificates()
		require.NoError(t, err)
		for _, c := range paired {
			if signer, ok := c.PrivateKey.(*pkcs11PrivateKeyECDSA); ok && signer.handle == keyHandle {
				return c.Leaf
			}
		}
		return nil
	}
	assert.Nil(t, leafFor(), "a certificate for another key was paired by CKA_ID alone")

	require.NoError(t, ctx.ImportCertificate(id, own))
	defer func() { _ = ctx.DeleteCertificate(id, nil, own.SerialNumber) }()
	if leaf := leafFor(); assert.NotNil(t, leaf) {
		assert.Equal(t, own.Raw, leaf.Raw)
	}

	// Without a public key object, the key pair's public half comes from a certificate; only
	// the one that certifies the key will do.
	destroyObject(t, ctx, key.(*pkcs11PrivateKeyECDSA).pubKeyHandle)
	defer destroyObject(t, ctx, keyHandle)
	found, err := ctx.FindKeyPair(id, nil)
	require.NoError(t, err)
	assert.True(t, publicKeysEqual(key.Public(), found.Public()))

	require.NoError(t, ctx.DeleteCertificate(id, nil, own.SerialNumber))
	_, err = ctx.FindKeyPair(id, nil)
	assert.Error(t, err, "a key pair was built from a certificate for another key")
}
