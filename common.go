// Copyright 2024 Thales Group
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package crypto11

import (
	"C"
	"encoding/asn1"
	"encoding/binary"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

func ulongToBytes(n uint) []byte {
	result := make([]byte, C.sizeof_ulong)
	putUlong(result, n)
	return result
}

// ulongsToBytes encodes several CK_ULONG values with one allocation. PKCS#11
// mechanism parameters are short-lived and must not be retained in a global
// pool because they may contain cryptographic metadata.
func ulongsToBytes(values ...uint) []byte {
	size := int(C.sizeof_ulong)
	result := make([]byte, size*len(values))
	for i, value := range values {
		putUlong(result[i*size:], value)
	}
	return result
}

func putUlong(dst []byte, n uint) {
	switch C.sizeof_ulong {
	case 4:
		binary.NativeEndian.PutUint32(dst, uint32(n))
	case 8:
		binary.NativeEndian.PutUint64(dst, uint64(n))
	default:
		panic("unsupported CK_ULONG size")
	}
}

func bytesToUlong(bs []byte) (n uint) {
	if len(bs) == 0 {
		return 0
	}

	// Attribute values can be shorter than CK_ULONG. Copying into a fixed-size
	// local buffer avoids the out-of-bounds read performed by the old unsafe
	// conversion while preserving native-endian PKCS#11 encoding.
	size := min(len(bs), int(C.sizeof_ulong))
	var buf [8]byte
	copy(buf[:size], bs[:size])
	switch C.sizeof_ulong {
	case 4:
		return uint(binary.NativeEndian.Uint32(buf[:4]))
	case 8:
		return uint(binary.NativeEndian.Uint64(buf[:8]))
	default:
		panic("unsupported CK_ULONG size")
	}
}

// Representation of a *DSA signature
type dsaSignature struct {
	R, S *big.Int
}

// Populate a dsaSignature from a raw byte sequence
func (sig *dsaSignature) unmarshalBytes(sigBytes []byte) error {
	if len(sigBytes) == 0 || len(sigBytes)%2 != 0 {
		return errors.New("DSA signature length is invalid from token")
	}
	n := len(sigBytes) / 2
	sig.R, sig.S = new(big.Int), new(big.Int)
	sig.R.SetBytes(sigBytes[:n])
	sig.S.SetBytes(sigBytes[n:])
	return nil
}

// Populate a dsaSignature from DER encoding
func (sig *dsaSignature) unmarshalDER(sigDER []byte) error {
	if rest, err := asn1.Unmarshal(sigDER, sig); err != nil {
		return errors.WithMessage(err, "DSA signature contains invalid ASN.1 data")
	} else if len(rest) > 0 {
		return errors.New("unexpected data found after DSA signature")
	}
	return nil
}

// Return the DER encoding of a dsaSignature
func (sig *dsaSignature) marshalDER() ([]byte, error) {
	return asn1.Marshal(*sig)
}

// Compute *DSA signature and marshal the result in DER form
func (c *Context) dsaGeneric(key pkcs11.ObjectHandle, mechanism uint, digest []byte) ([]byte, error) {
	var err error
	var sigBytes []byte
	var sig dsaSignature
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, nil)}
	err = c.withSession(func(session *pkcs11Session) error {
		if err = c.ctx.SignInit(session.handle, mech, key); err != nil {
			return err
		}
		sigBytes, err = c.ctx.Sign(session.handle, digest)
		return err
	})
	if err != nil {
		return nil, err
	}
	err = sig.unmarshalBytes(sigBytes)
	if err != nil {
		return nil, err
	}

	return sig.marshalDER()
}
