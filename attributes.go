// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"fmt"
	"strings"

	pkcs11 "github.com/ad3n/pkcs11-go/cryptoki"
)

// AttributeType represents a PKCS#11 CK_ATTRIBUTE value.
type AttributeType = uint

// Attribute represents a PKCS#11 CK_ATTRIBUTE type.
type Attribute = pkcs11.Attribute

// The Cka* constants predate crypto11's move to the pkcs11-go binding, whose
// cryptoki package is generated from the OASIS PKCS #11 v3.2 header and defines
// every CKA_* attribute, including the ones added since this list was written
// (CKA_UNIQUE_ID, CKA_PROFILE_ID, CKA_SEED, CKA_PUBLIC_CRC64_VALUE, ...). Each
// Cka* constant is now the binding's constant of the same name, still typed
// AttributeType, so code using them keeps compiling and behaves as before. The
// binding's constants are untyped, so they can be passed anywhere an
// AttributeType is expected.
//
// Deprecated: Use the CKA_* constants of github.com/ad3n/pkcs11-go/cryptoki,
// e.g. pkcs11.CKA_LABEL instead of CkaLabel.
const (
	CkaClass                  = AttributeType(pkcs11.CKA_CLASS)
	CkaToken                  = AttributeType(pkcs11.CKA_TOKEN)
	CkaPrivate                = AttributeType(pkcs11.CKA_PRIVATE)
	CkaLabel                  = AttributeType(pkcs11.CKA_LABEL)
	CkaApplication            = AttributeType(pkcs11.CKA_APPLICATION)
	CkaValue                  = AttributeType(pkcs11.CKA_VALUE)
	CkaObjectId               = AttributeType(pkcs11.CKA_OBJECT_ID)
	CkaCertificateType        = AttributeType(pkcs11.CKA_CERTIFICATE_TYPE)
	CkaIssuer                 = AttributeType(pkcs11.CKA_ISSUER)
	CkaSerialNumber           = AttributeType(pkcs11.CKA_SERIAL_NUMBER)
	CkaAcIssuer               = AttributeType(pkcs11.CKA_AC_ISSUER)
	CkaOwner                  = AttributeType(pkcs11.CKA_OWNER)
	CkaAttrTypes              = AttributeType(pkcs11.CKA_ATTR_TYPES)
	CkaTrusted                = AttributeType(pkcs11.CKA_TRUSTED)
	CkaCertificateCategory    = AttributeType(pkcs11.CKA_CERTIFICATE_CATEGORY)
	CkaJavaMIDPSecurityDomain = AttributeType(pkcs11.CKA_JAVA_MIDP_SECURITY_DOMAIN)
	CkaUrl                    = AttributeType(pkcs11.CKA_URL)
	CkaHashOfSubjectPublicKey = AttributeType(pkcs11.CKA_HASH_OF_SUBJECT_PUBLIC_KEY)
	CkaHashOfIssuerPublicKey  = AttributeType(pkcs11.CKA_HASH_OF_ISSUER_PUBLIC_KEY)
	CkaNameHashAlgorithm      = AttributeType(pkcs11.CKA_NAME_HASH_ALGORITHM)
	CkaCheckValue             = AttributeType(pkcs11.CKA_CHECK_VALUE)

	CkaKeyType         = AttributeType(pkcs11.CKA_KEY_TYPE)
	CkaSubject         = AttributeType(pkcs11.CKA_SUBJECT)
	CkaId              = AttributeType(pkcs11.CKA_ID)
	CkaSensitive       = AttributeType(pkcs11.CKA_SENSITIVE)
	CkaEncrypt         = AttributeType(pkcs11.CKA_ENCRYPT)
	CkaDecrypt         = AttributeType(pkcs11.CKA_DECRYPT)
	CkaWrap            = AttributeType(pkcs11.CKA_WRAP)
	CkaUnwrap          = AttributeType(pkcs11.CKA_UNWRAP)
	CkaSign            = AttributeType(pkcs11.CKA_SIGN)
	CkaSignRecover     = AttributeType(pkcs11.CKA_SIGN_RECOVER)
	CkaVerify          = AttributeType(pkcs11.CKA_VERIFY)
	CkaVerifyRecover   = AttributeType(pkcs11.CKA_VERIFY_RECOVER)
	CkaDerive          = AttributeType(pkcs11.CKA_DERIVE)
	CkaStartDate       = AttributeType(pkcs11.CKA_START_DATE)
	CkaEndDate         = AttributeType(pkcs11.CKA_END_DATE)
	CkaModulus         = AttributeType(pkcs11.CKA_MODULUS)
	CkaModulusBits     = AttributeType(pkcs11.CKA_MODULUS_BITS)
	CkaPublicExponent  = AttributeType(pkcs11.CKA_PUBLIC_EXPONENT)
	CkaPrivateExponent = AttributeType(pkcs11.CKA_PRIVATE_EXPONENT)
	CkaPrime1          = AttributeType(pkcs11.CKA_PRIME_1)
	CkaPrime2          = AttributeType(pkcs11.CKA_PRIME_2)
	CkaExponent1       = AttributeType(pkcs11.CKA_EXPONENT_1)
	CkaExponent2       = AttributeType(pkcs11.CKA_EXPONENT_2)
	CkaCoefficient     = AttributeType(pkcs11.CKA_COEFFICIENT)
	CkaPublicKeyInfo   = AttributeType(pkcs11.CKA_PUBLIC_KEY_INFO)
	CkaPrime           = AttributeType(pkcs11.CKA_PRIME)
	CkaSubprime        = AttributeType(pkcs11.CKA_SUBPRIME)
	CkaBase            = AttributeType(pkcs11.CKA_BASE)

	CkaPrimeBits    = AttributeType(pkcs11.CKA_PRIME_BITS)
	CkaSubprimeBits = AttributeType(pkcs11.CKA_SUBPRIME_BITS)
	/* (To retain backwards-compatibility) */
	CkaSubPrimeBits = AttributeType(pkcs11.CKA_SUB_PRIME_BITS)

	CkaValueBits        = AttributeType(pkcs11.CKA_VALUE_BITS)
	CkaValueLen         = AttributeType(pkcs11.CKA_VALUE_LEN)
	CkaExtractable      = AttributeType(pkcs11.CKA_EXTRACTABLE)
	CkaLocal            = AttributeType(pkcs11.CKA_LOCAL)
	CkaNeverExtractable = AttributeType(pkcs11.CKA_NEVER_EXTRACTABLE)
	CkaAlwaysSensitive  = AttributeType(pkcs11.CKA_ALWAYS_SENSITIVE)
	CkaKeyGenMechanism  = AttributeType(pkcs11.CKA_KEY_GEN_MECHANISM)

	CkaModifiable = AttributeType(pkcs11.CKA_MODIFIABLE)
	CkaCopyable   = AttributeType(pkcs11.CKA_COPYABLE)

	/* new for v2.40 */
	CkaDestroyable = AttributeType(pkcs11.CKA_DESTROYABLE)

	/* CKA_ECDSA_PARAMS is deprecated in v2.11,
	 * CKA_EC_PARAMS is preferred. */
	CkaEcdsaParams = AttributeType(pkcs11.CKA_ECDSA_PARAMS)
	CkaEcParams    = AttributeType(pkcs11.CKA_EC_PARAMS)

	CkaEcPoint = AttributeType(pkcs11.CKA_EC_POINT)

	/* CKA_SECONDARY_AUTH, CKA_AUTH_PIN_FLAGS,
	 * are new for v2.10. Deprecated in v2.11 and onwards. */
	CkaSecondaryAuth = AttributeType(pkcs11.CKA_SECONDARY_AUTH)
	CkaAuthPinFlags  = AttributeType(pkcs11.CKA_AUTH_PIN_FLAGS)

	CkaAlwaysAuthenticate = AttributeType(pkcs11.CKA_ALWAYS_AUTHENTICATE)

	CkaWrapWithTrusted = AttributeType(pkcs11.CKA_WRAP_WITH_TRUSTED)

	CkaWrapTemplate   = AttributeType(pkcs11.CKA_WRAP_TEMPLATE)
	CkaUnwrapTemplate = AttributeType(pkcs11.CKA_UNWRAP_TEMPLATE)

	CkaOtpFormat               = AttributeType(pkcs11.CKA_OTP_FORMAT)
	CkaOtpLength               = AttributeType(pkcs11.CKA_OTP_LENGTH)
	CkaOtpTimeInterval         = AttributeType(pkcs11.CKA_OTP_TIME_INTERVAL)
	CkaOtpUserFriendlyMode     = AttributeType(pkcs11.CKA_OTP_USER_FRIENDLY_MODE)
	CkaOtpChallengeRequirement = AttributeType(pkcs11.CKA_OTP_CHALLENGE_REQUIREMENT)
	CkaOtpTimeRequirement      = AttributeType(pkcs11.CKA_OTP_TIME_REQUIREMENT)
	CkaOtpCounterRequirement   = AttributeType(pkcs11.CKA_OTP_COUNTER_REQUIREMENT)
	CkaOtpPinRequirement       = AttributeType(pkcs11.CKA_OTP_PIN_REQUIREMENT)
	CkaOtpCounter              = AttributeType(pkcs11.CKA_OTP_COUNTER)
	CkaOtpTime                 = AttributeType(pkcs11.CKA_OTP_TIME)
	CkaOtpUserIdentifier       = AttributeType(pkcs11.CKA_OTP_USER_IDENTIFIER)
	CkaOtpServiceIdentifier    = AttributeType(pkcs11.CKA_OTP_SERVICE_IDENTIFIER)
	CkaOtpServiceLogo          = AttributeType(pkcs11.CKA_OTP_SERVICE_LOGO)
	CkaOtpServiceLogoType      = AttributeType(pkcs11.CKA_OTP_SERVICE_LOGO_TYPE)

	CkaGOSTR3410Params = AttributeType(pkcs11.CKA_GOSTR3410_PARAMS)
	CkaGOSTR3411Params = AttributeType(pkcs11.CKA_GOSTR3411_PARAMS)
	CkaGOST28147Params = AttributeType(pkcs11.CKA_GOST28147_PARAMS)

	CkaHwFeatureType = AttributeType(pkcs11.CKA_HW_FEATURE_TYPE)
	CkaResetOnInit   = AttributeType(pkcs11.CKA_RESET_ON_INIT)
	CkaHasReset      = AttributeType(pkcs11.CKA_HAS_RESET)

	CkaPixelX                 = AttributeType(pkcs11.CKA_PIXEL_X)
	CkaPixelY                 = AttributeType(pkcs11.CKA_PIXEL_Y)
	CkaResolution             = AttributeType(pkcs11.CKA_RESOLUTION)
	CkaCharRows               = AttributeType(pkcs11.CKA_CHAR_ROWS)
	CkaCharColumns            = AttributeType(pkcs11.CKA_CHAR_COLUMNS)
	CkaColor                  = AttributeType(pkcs11.CKA_COLOR)
	CkaBitsPerPixel           = AttributeType(pkcs11.CKA_BITS_PER_PIXEL)
	CkaCharSets               = AttributeType(pkcs11.CKA_CHAR_SETS)
	CkaEncodingMethods        = AttributeType(pkcs11.CKA_ENCODING_METHODS)
	CkaMimeTypes              = AttributeType(pkcs11.CKA_MIME_TYPES)
	CkaMechanismType          = AttributeType(pkcs11.CKA_MECHANISM_TYPE)
	CkaRequiredCmsAttributes  = AttributeType(pkcs11.CKA_REQUIRED_CMS_ATTRIBUTES)
	CkaDefaultCmsAttributes   = AttributeType(pkcs11.CKA_DEFAULT_CMS_ATTRIBUTES)
	CkaSupportedCmsAttributes = AttributeType(pkcs11.CKA_SUPPORTED_CMS_ATTRIBUTES)
	CkaAllowedMechanisms      = AttributeType(pkcs11.CKA_ALLOWED_MECHANISMS)

	/* new for v3.2 (PKCS#11 v3.2, KEM / post-quantum) */
	CkaParameterSet        = AttributeType(pkcs11.CKA_PARAMETER_SET)
	CkaEncapsulateTemplate = AttributeType(pkcs11.CKA_ENCAPSULATE_TEMPLATE)
	CkaDecapsulateTemplate = AttributeType(pkcs11.CKA_DECAPSULATE_TEMPLATE)
	CkaEncapsulate         = AttributeType(pkcs11.CKA_ENCAPSULATE)
	CkaDecapsulate         = AttributeType(pkcs11.CKA_DECAPSULATE)
)

// NewAttribute is a helper function that populates a new Attribute for common data types. This function will
// return an error if value is not of type bool, int, uint, string, []byte or time.Time (or is nil).
func NewAttribute(attributeType AttributeType, value interface{}) (a *Attribute, err error) {
	// catch any panics from the pkcs11.NewAttribute() call to keyHandle the error cleanly
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed creating Attribute: %v", r)
		}
	}()

	pAttr := pkcs11.NewAttribute(attributeType, value)
	return pAttr, nil
}

// CopyAttribute returns a deep copy of the given Attribute.
func CopyAttribute(a *Attribute) *Attribute {
	var value []byte
	if len(a.Value) > 0 {
		value = append([]byte(nil), a.Value...)
	}
	return &pkcs11.Attribute{
		Type:  a.Type,
		Value: value,
	}
}

// An AttributeSet groups together operations that are common for a collection of Attributes.
type AttributeSet map[AttributeType]*Attribute

// NewAttributeSet creates an empty AttributeSet.
func NewAttributeSet() AttributeSet {
	return make(AttributeSet)
}

// Set stores a new attribute in the AttributeSet. Any existing value will be overwritten. This function will return an
// error if value is not of type bool, int, uint, string, []byte or time.Time (or is nil).
func (a AttributeSet) Set(attributeType AttributeType, value interface{}) error {
	attr, err := NewAttribute(attributeType, value)
	if err != nil {
		return err
	}
	a[attributeType] = attr
	return nil
}

// cloneFrom make this AttributeSet a clone of the supplied set. Values are deep copied.
func (a AttributeSet) cloneFrom(set AttributeSet) {
	for key := range a {
		delete(a, key)
	}

	// Use Copy to do the deep cloning for us
	c := set.Copy()
	for k, v := range c {
		a[k] = v
	}
}

// AddIfNotPresent adds the attributes if the Attribute Type is not already present in the AttributeSet.
func (a AttributeSet) AddIfNotPresent(additional []*Attribute) {
	for _, additionalAttr := range additional {
		// Only add the attribute if it is not already present in the Attribute map
		if _, ok := a[additionalAttr.Type]; !ok {
			a[additionalAttr.Type] = additionalAttr
		}
	}
}

// ToSlice returns a deep copy of Attributes contained in the AttributeSet.
func (a AttributeSet) ToSlice() []*Attribute {
	attributes := make([]*Attribute, 0, len(a))
	for _, v := range a {
		duplicateAttr := CopyAttribute(v)
		attributes = append(attributes, duplicateAttr)
	}
	return attributes
}

// Copy returns a deep copy of the AttributeSet. This function will return an error if value is not of type
// bool, int, uint, string, []byte or time.Time (or is nil).
func (a AttributeSet) Copy() AttributeSet {
	b := make(AttributeSet, len(a))
	for _, v := range a {
		b[v.Type] = CopyAttribute(v)
	}
	return b
}

// Unset removes an attribute from the attributes set. If the set does not contain the attribute, this
// is a no-op.
func (a AttributeSet) Unset(attributeType AttributeType) {
	delete(a, attributeType)
}

// String renders the set for logs and error messages, one attribute per line
// under its CKA_ name (cryptoki.AttributeName). The values of attributes that
// can carry key material are replaced by their length: a set
// built to import a key, or read back with GetAttributes, may hold a secret
// key's CKA_VALUE or an RSA private key's CRT components, and %v on it should
// not put those in a log line.
func (a AttributeSet) String() string {
	result := new(strings.Builder)
	for attr, value := range a {
		if sensitiveAttribute(attr) {
			_, _ = fmt.Fprintf(result, "%s: <redacted, %d bytes>\n", pkcs11.AttributeName(attr), len(value.Value))
			continue
		}
		_, _ = fmt.Fprintf(result, "%s: %x\n", pkcs11.AttributeName(attr), value.Value)
	}
	return result.String()
}

// sensitiveAttribute reports whether an attribute's value may be key material.
// CKA_VALUE is the value of a secret key and of a DSA, EC or ML-KEM private
// key (it is also the DER of a certificate and the Y of a DSA public key, but
// String cannot tell the object class, so it errs on the side of redaction);
// CKA_SEED is the seed an ML-KEM, ML-DSA or SLH-DSA private key is expanded
// from; the six others are the RSA private key's components. Vendor-defined
// attributes are redacted as well, since nothing here knows what they hold.
func sensitiveAttribute(attr AttributeType) bool {
	switch attr {
	case pkcs11.CKA_VALUE, pkcs11.CKA_SEED, pkcs11.CKA_PRIVATE_EXPONENT, pkcs11.CKA_PRIME_1, pkcs11.CKA_PRIME_2, pkcs11.CKA_EXPONENT_1, pkcs11.CKA_EXPONENT_2, pkcs11.CKA_COEFFICIENT:
		return true
	}
	return attr >= pkcs11.CKA_VENDOR_DEFINED
}

// NewAttributeSetWithID is a helper function that populates a new slice of Attributes with the provided ID.
// This function returns an error if the ID is an empty slice.
func NewAttributeSetWithID(id []byte) (AttributeSet, error) {
	if err := notNilBytes(id, "id"); err != nil {
		return nil, err
	}
	a := NewAttributeSet()
	_ = a.Set(pkcs11.CKA_ID, id) // error not possible for []byte
	return a, nil
}

// NewAttributeSetWithIDAndLabel is a helper function that populates a new slice of Attributes with the
// provided ID and Label. This function returns an error if either the ID or the Label is an empty slice.
func NewAttributeSetWithIDAndLabel(id, label []byte) (a AttributeSet, err error) {
	if a, err = NewAttributeSetWithID(id); err != nil {
		return nil, err
	}

	if err := notNilBytes(label, "label"); err != nil {
		return nil, err
	}

	_ = a.Set(pkcs11.CKA_LABEL, label) // error not possible with []byte
	return a, nil
}
