// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"errors"
	"fmt"
	"hash"

	pkcs11 "github.com/ad3n/pkcs11-go/cryptoki"
)

const (
	// NFCK_VENDOR_NCIPHER distinguishes nShield vendor-specific mechanisms.
	NFCK_VENDOR_NCIPHER = 0xde436972

	// CKM_NCIPHER is the base for nShield vendor-specific mechanisms.
	CKM_NCIPHER = pkcs11.CKM_VENDOR_DEFINED | NFCK_VENDOR_NCIPHER

	// CKM_NC_MD5_HMAC_KEY_GEN is the nShield-specific HMACMD5 key-generation mechanism
	CKM_NC_MD5_HMAC_KEY_GEN = CKM_NCIPHER + 0x6

	// CKM_NC_SHA_1_HMAC_KEY_GEN is the nShield-specific HMACSHA1 key-generation mechanism
	CKM_NC_SHA_1_HMAC_KEY_GEN = CKM_NCIPHER + 0x3

	// CKM_NC_SHA224_HMAC_KEY_GEN is the nShield-specific HMACSHA224 key-generation mechanism
	CKM_NC_SHA224_HMAC_KEY_GEN = CKM_NCIPHER + 0x24

	// CKM_NC_SHA256_HMAC_KEY_GEN is the nShield-specific HMACSHA256 key-generation mechanism
	CKM_NC_SHA256_HMAC_KEY_GEN = CKM_NCIPHER + 0x25

	// CKM_NC_SHA384_HMAC_KEY_GEN is the nShield-specific HMACSHA384 key-generation mechanism
	CKM_NC_SHA384_HMAC_KEY_GEN = CKM_NCIPHER + 0x26

	// CKM_NC_SHA512_HMAC_KEY_GEN is the nShield-specific HMACSHA512 key-generation mechanism
	CKM_NC_SHA512_HMAC_KEY_GEN = CKM_NCIPHER + 0x27
)

// KeyedHash is a hash.Hash that is a keyed MAC (HMAC) rather than a bare digest.
//
// crypto/hmac's concrete type is unexported, so a consumer cannot recognise a
// keyed MAC by type assertion alone. A keyed MAC implemented outside crypto/hmac
// — for example the HSM-backed HMAC returned by SecretKey.NewHMAC — opts in by
// implementing this interface, which lets such a consumer accept it while still
// rejecting an unkeyed digest such as sha256.New().
type KeyedHash interface {
	hash.Hash
	// IsKeyedHash marks the implementation as a keyed MAC. It carries no
	// behaviour; it exists only to make keyed-ness explicit and checkable.
	IsKeyedHash()
}

type hmacImplementation struct {
	session         *pkcs11Session
	key             *SecretKey
	cleanup         func(err error)
	mechDescription *pkcs11.Mechanism
	result          []byte
	size            int
	blockSize       int
	updates         uint64
}

// IsKeyedHash marks hmacImplementation as a keyed MAC. It satisfies the
// KeyedHash interface (and, structurally, gose.KeyedHash) so that consumers
// requiring a keyed MAC accept the HSM-backed HMAC returned by NewHMAC.
func (*hmacImplementation) IsKeyedHash() {}

// hmacImplementation is a keyed MAC; keep the marker in place.
var _ KeyedHash = (*hmacImplementation)(nil)

type hmacInfo struct {
	size      int
	blockSize int
	general   bool
}

var hmacInfos = map[int]*hmacInfo{
	pkcs11.CKM_MD5_HMAC:                {16, 64, false},
	pkcs11.CKM_MD5_HMAC_GENERAL:        {16, 64, true},
	pkcs11.CKM_SHA_1_HMAC:              {20, 64, false},
	pkcs11.CKM_SHA_1_HMAC_GENERAL:      {20, 64, true},
	pkcs11.CKM_SHA224_HMAC:             {28, 64, false},
	pkcs11.CKM_SHA224_HMAC_GENERAL:     {28, 64, true},
	pkcs11.CKM_SHA256_HMAC:             {32, 64, false},
	pkcs11.CKM_SHA256_HMAC_GENERAL:     {32, 64, true},
	pkcs11.CKM_SHA384_HMAC:             {48, 128, false},
	pkcs11.CKM_SHA384_HMAC_GENERAL:     {48, 128, true},
	pkcs11.CKM_SHA512_HMAC:             {64, 128, false},
	pkcs11.CKM_SHA512_HMAC_GENERAL:     {64, 128, true},
	pkcs11.CKM_SHA512_224_HMAC:         {28, 128, false},
	pkcs11.CKM_SHA512_224_HMAC_GENERAL: {28, 128, true},
	pkcs11.CKM_SHA512_256_HMAC:         {32, 128, false},
	pkcs11.CKM_SHA512_256_HMAC_GENERAL: {32, 128, true},
	pkcs11.CKM_RIPEMD160_HMAC:          {20, 64, false},
	pkcs11.CKM_RIPEMD160_HMAC_GENERAL:  {20, 64, true},
}

// errHmacClosed is called if an HMAC is updated after it has finished.
var errHmacClosed = errors.New("already called Sum()")

// errInvalidMACLength is returned by NewHMAC for an output length the
// mechanism cannot produce.
var errInvalidMACLength = errors.New("invalid MAC length")

// NewHMAC returns a new HMAC hash using the given PKCS#11 mechanism
// and key.
// length specifies the output size, for _GENERAL mechanisms: between 1 and the
// full MAC size of the underlying hash.
//
// If the mechanism is not in the built-in list of known mechanisms then the
// Size() function will return whatever length was, even if it is wrong.
// BlockSize() will always return 0 in this case.
//
// Reset finishes any operation in progress and starts a new one on a fresh
// session; if that session cannot be obtained the hash is dead — Write returns
// an error and Sum panics — rather than replaying the previous result.
// After Sum() is called no new data may be added.
//
// Failure handling: the returned hash.Hash cannot report errors through Sum,
// whose signature is fixed by the interface. If the underlying HSM operation
// fails (for example the session is lost mid-operation), Write returns an error
// and a subsequent Sum panics rather than returning a bogus MAC. Callers that
// must tolerate HSM faults should surface the Write error and/or wrap Sum in a
// recover().
func (key *SecretKey) NewHMAC(mech int, length int) (hash.Hash, error) {
	hi := hmacImplementation{
		key: key,
	}
	var params []byte
	if info, ok := hmacInfos[mech]; ok {
		hi.blockSize = info.blockSize
		if info.general {
			// A zero length would make every Sum panic on the empty MAC, and a
			// negative one would reach the token as a huge CK_ULONG.
			if length < 1 || length > info.size {
				return nil, fmt.Errorf("%w: %d bytes; mechanism %#x produces 1 to %d", errInvalidMACLength, length, mech, info.size)
			}
			hi.size = length
			params = pkcs11.ULongToBytes(uint(length))
		} else {
			hi.size = info.size
		}
	} else {
		if length < 0 {
			return nil, fmt.Errorf("%w: %d bytes", errInvalidMACLength, length)
		}
		hi.size = length
	}
	hi.mechDescription = pkcs11.NewMechanism(uint(mech), params)
	if err := hi.initialize(); err != nil {
		return nil, err
	}
	return &hi, nil
}

func (hi *hmacImplementation) initialize() (err error) {
	session, err := hi.key.context.getSession()
	if err != nil {
		return err
	}

	hi.session = session
	// Idempotent: a multi-part HMAC can fail at several points, each of which must
	// release the session. Returning the same session to the pool twice would hand it
	// to two concurrent callers (session-state corruption / cross-operation leakage),
	// so guard on the nil sentinel.
	hi.cleanup = func(err error) {
		if hi.session == nil {
			return
		}
		hi.key.context.putSession(session, err)
		hi.session = nil
	}
	if err = hi.session.ctx.SignInit(hi.session.handle, hi.mechDescription, hi.key.handle); err != nil {
		hi.cleanup(err)
		return
	}
	hi.updates = 0
	hi.result = nil
	return
}

func (hi *hmacImplementation) Write(p []byte) (n int, err error) {
	if hi.result != nil {
		if len(p) > 0 {
			err = errHmacClosed
		}
		return
	}
	if hi.session == nil {
		// A previous step failed and released the session; the operation is dead.
		err = errHmacClosed
		return
	}
	if err = hi.session.ctx.SignUpdate(hi.session.handle, p); err != nil {
		// The operation is dead. Release the session now, because Sum (which normally
		// performs cleanup) will not be reached.
		hi.cleanup(err)
		return
	}
	hi.updates++
	n = len(p)
	return
}

func (hi *hmacImplementation) Sum(b []byte) []byte {
	if hi.result == nil {
		if hi.session == nil {
			// A previous step failed and released the session, so there is no result.
			// Returning a zero-length value would silently yield a bogus HMAC; panic to
			// match the existing finalize-failure behaviour instead.
			panic(errHmacClosed)
		}
		var err error
		if hi.updates == 0 {
			// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc322855304
			// We must ensure that C_SignUpdate is called _at least once_.
			if err = hi.session.ctx.SignUpdate(hi.session.handle, []byte{}); err != nil {
				hi.cleanup(err)
				panic(err)
			}
		}
		result, err := hi.session.ctx.SignFinal(hi.session.handle)
		hi.cleanup(err)
		if err != nil {
			panic(err)
		}
		// Only a MAC of the size the mechanism promises is cached. A token that
		// answers with an empty or truncated tag — through a defect, or because
		// it was tampered with — would otherwise hand the caller something a
		// verifier could be made to accept.
		if err := checkMACLength(result, hi.size); err != nil {
			panic(err)
		}
		hi.result = result
	}
	return append(b, hi.result...)
}

// checkMACLength rejects a token-returned MAC that is empty or, when the
// expected size is known, of any other length. size is zero only for a
// mechanism outside hmacInfos used with length 0, in which case there is
// nothing to compare against beyond emptiness.
func checkMACLength(result []byte, size int) error {
	if len(result) == 0 || (size > 0 && len(result) != size) {
		return fmt.Errorf("token returned a %d-byte MAC where %d bytes were expected", len(result), size)
	}
	return nil
}

// Reset finishes any operation in progress and starts a new one.
func (hi *hmacImplementation) Reset() {
	if hi.session != nil {
		// A multi-part operation is still open on the session: finalize it so
		// the session goes back to the pool without a dangling C_SignInit.
		hi.Sum(nil)
	}

	// Forget the previous MAC before trying to reinitialize. Should the new
	// session be unobtainable, a stale result here would make the next Sum
	// return the previous message's tag as if it authenticated the new input.
	// With result and session both nil the hash is dead: Write errors, Sum
	// panics, which is what a token failure mid-operation already produces.
	hi.result = nil

	// Assign the error to "_" to indicate we are knowingly ignoring this. It may have been
	// sensible to panic at this stage, but we cannot add a panic without breaking backwards
	// compatibility.
	_ = hi.initialize()
}

func (hi *hmacImplementation) Size() int {
	return hi.size
}

func (hi *hmacImplementation) BlockSize() int {
	return hi.blockSize
}
