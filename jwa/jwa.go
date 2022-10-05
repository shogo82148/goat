// Package jwa implements RFC 7518.
package jwa

import (
	"github.com/shogo82148/goat/enc"
	"github.com/shogo82148/goat/keymanage"
	"github.com/shogo82148/goat/sig"
)

// SignatureAlgorithm is an algorithm for JSON Web Signature (JWS)
// defined in the IANA "JSON Web Signature and Encryption Algorithms".
type SignatureAlgorithm string

const (
	SignatureAlgorithmUnknown SignatureAlgorithm = ""

	// HS256 is HMAC using SHA-256.
	// import github.com/shogo82148/goat/jwa/hs
	HS256 SignatureAlgorithm = "HS256"

	// HS384 is HMAC using SHA-384.
	// import github.com/shogo82148/goat/jwa/hs
	HS384 SignatureAlgorithm = "HS384"

	// HS512 is HMAC using SHA-512.
	// import github.com/shogo82148/goat/jwa/hs
	HS512 SignatureAlgorithm = "HS512"

	// RS256 is RSASSA-PKCS1-v1_5 using SHA-256.
	// import github.com/shogo82148/goat/jwa/rs
	RS256 SignatureAlgorithm = "RS256"

	// RS384 is RSASSA-PKCS1-v1_5 using SHA-384.
	// import github.com/shogo82148/goat/jwa/rs
	RS384 SignatureAlgorithm = "RS384"

	// RS512 is RSASSA-PKCS1-v1_5 using SHA-512.
	// import github.com/shogo82148/goat/jwa/rs
	RS512 SignatureAlgorithm = "RS512"

	// ES256 is ECDSA using P-256 and SHA-256.
	// import github.com/shogo82148/goat/jwa/es
	ES256 SignatureAlgorithm = "ES256"

	// ES384 is ECDSA using P-384 and SHA-384.
	// import github.com/shogo82148/goat/jwa/es
	ES384 SignatureAlgorithm = "ES384"

	// ES512 is ECDSA using P-521 and SHA-512.
	// import github.com/shogo82148/goat/jwa/es
	ES512 SignatureAlgorithm = "ES512"

	// PS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
	// import github.com/shogo82148/goat/jwa/ps
	PS256 SignatureAlgorithm = "PS256"

	// PS384 is RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
	// import github.com/shogo82148/goat/jwa/ps
	PS384 SignatureAlgorithm = "PS384"

	// PS512 is RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
	// import github.com/shogo82148/goat/jwa/ps
	PS512 SignatureAlgorithm = "PS512"

	// None is no digital signature or MAC performed.
	// import github.com/shogo82148/goat/jwa/none
	None SignatureAlgorithm = "none"

	// EdDSA is Edwards-Curve Digital Signature Algorithm.
	// import github.com/shogo82148/goat/jwa/eddsa
	EdDSA SignatureAlgorithm = "EdDSA"
)

func (alg SignatureAlgorithm) String() string {
	return string(alg)
}

func (alg SignatureAlgorithm) KeyAlgorithm() KeyAlgorithm {
	return KeyAlgorithm(alg)
}

func (alg SignatureAlgorithm) New() sig.Algorithm {
	f := signatureAlgorithms[alg]
	if f == nil {
		panic("jwa: requested signature algorithm " + alg.String() + " is not available")
	}
	return f()
}

func (alg SignatureAlgorithm) Available() bool {
	f := signatureAlgorithms[alg]
	return f != nil
}

var signatureAlgorithms = map[SignatureAlgorithm]func() sig.Algorithm{
	HS256: nil,
	HS384: nil,
	HS512: nil,
	RS256: nil,
	RS384: nil,
	RS512: nil,
	ES256: nil,
	ES384: nil,
	ES512: nil,
	PS256: nil,
	PS384: nil,
	PS512: nil,
	None:  nil,
	EdDSA: nil,
}

func RegisterSignatureAlgorithm(alg SignatureAlgorithm, f func() sig.Algorithm) {
	g, ok := signatureAlgorithms[alg]
	if !ok {
		panic("jwa: RegisterSignatureAlgorithm of unknown algorithm")
	}
	if g != nil {
		panic("jwa: RegisterSignatureAlgorithm of already registered algorithm")
	}
	signatureAlgorithms[alg] = f
}

// KeyManagementAlgorithm is an algorithm for JSON Web Encryption (JWE)
// defined in the IANA JSON Web Signature and Encryption Algorithms.
type KeyManagementAlgorithm string

const (
	KeyManagementAlgorithmUnknown KeyManagementAlgorithm = ""

	// RSA1_5 is RSAES-PKCS1-v1_5.
	// import github.com/shogo82148/goat/jwa/rsapkcs1v15
	RSA1_5 KeyManagementAlgorithm = "RSA1_5"

	// RSA_OAEP is RSAES OAEP using.
	// import github.com/shogo82148/goat/jwa/rsapoaep
	RSA_OAEP KeyManagementAlgorithm = "RSA-OAEP"

	// RSA_OAEP_256 is RSAES OAEP using SHA-256 and MGF1 with SHA-256.
	// import github.com/shogo82148/goat/jwa/rsapoaep
	RSA_OAEP_256 KeyManagementAlgorithm = "RSA-OAEP-256"

	// A128KW is AES Key Wrap with default initial value using 128-bit key.
	// import github.com/shogo82148/goat/jwa/akw
	A128KW KeyManagementAlgorithm = "A128KW"

	// A192KW is AES Key Wrap with default initial value using 192-bit key.
	// import github.com/shogo82148/goat/jwa/akw
	A192KW KeyManagementAlgorithm = "A192KW"

	// A256KW is AES Key Wrap with default initial value using 256-bit key.
	// import github.com/shogo82148/goat/jwa/akw
	A256KW KeyManagementAlgorithm = "A256KW"

	// Direct is direct use of a shared symmetric key as the CEK.
	// import github.com/shogo82148/goat/jwa/dir
	Direct KeyManagementAlgorithm = "dir"

	// ECDH_ES is Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF.
	// import github.com/shogo82148/goat/jwa/ecdhes
	ECDH_ES KeyManagementAlgorithm = "ECDH-ES"

	// ECDH_ES_A128KW is ECDH-ES using Concat KDF and CEK wrapped with "A128KW".
	// import github.com/shogo82148/goat/jwa/ecdhes
	ECDH_ES_A128KW KeyManagementAlgorithm = "ECDH-ES+A128KW"

	// ECDH_ES_A192KW is ECDH-ES using Concat KDF and CEK wrapped with "A192KW".
	// import github.com/shogo82148/goat/jwa/ecdhes
	ECDH_ES_A192KW KeyManagementAlgorithm = "ECDH-ES+A192KW"

	// ECDH_ES_A256KW is ECDH-ES using Concat KDF and CEK wrapped with "A256KW".
	// import github.com/shogo82148/goat/jwa/ecdhes
	ECDH_ES_A256KW KeyManagementAlgorithm = "ECDH-ES+A256KW"

	// A128GCMKW is Key wrapping with AES GCM using 128-bit key.
	// import github.com/shogo82148/goat/jwa/agcmkw
	A128GCMKW KeyManagementAlgorithm = "A128GCMKW"

	// A196GCMKW is Key wrapping with AES GCM using 196-bit key.
	// import github.com/shogo82148/goat/jwa/agcmkw
	A192GCMKW KeyManagementAlgorithm = "A192GCMKW"

	// A256GCMKW is Key wrapping with AES GCM using 256-bit key.
	// import github.com/shogo82148/goat/jwa/agcmkw
	A256GCMKW KeyManagementAlgorithm = "A256GCMKW"

	// PBES2_HS256_A128KW is PBES2 with HMAC SHA-256 and "A128KW" wrapping.
	// import github.com/shogo82148/goat/jwa/pbes2
	PBES2_HS256_A128KW KeyManagementAlgorithm = "PBES2-HS256+A128KW"

	// PBES2_HS384_A192KW is PBES2 with HMAC SHA-384 and "A192KW" wrapping.
	// import github.com/shogo82148/goat/jwa/pbes2
	PBES2_HS384_A192KW KeyManagementAlgorithm = "PBES2-HS384+A192KW"

	// PBES2_HS512_A256KW is PBES2 with HMAC SHA-512 and "A256KW" wrapping.
	// import github.com/shogo82148/goat/jwa/pbes2
	PBES2_HS512_A256KW KeyManagementAlgorithm = "PBES2-HS512+A256KW"
)

var keyManagementAlgorithms = map[KeyManagementAlgorithm]func() keymanage.Algorithm{
	RSA1_5:             nil,
	RSA_OAEP:           nil,
	RSA_OAEP_256:       nil,
	A128KW:             nil,
	A192KW:             nil,
	A256KW:             nil,
	Direct:             nil,
	ECDH_ES:            nil,
	ECDH_ES_A128KW:     nil,
	ECDH_ES_A192KW:     nil,
	ECDH_ES_A256KW:     nil,
	A128GCMKW:          nil,
	A192GCMKW:          nil,
	A256GCMKW:          nil,
	PBES2_HS256_A128KW: nil,
	PBES2_HS384_A192KW: nil,
	PBES2_HS512_A256KW: nil,
}

func RegisterKeyManagementAlgorithm(alg KeyManagementAlgorithm, f func() keymanage.Algorithm) {
	g, ok := keyManagementAlgorithms[alg]
	if !ok {
		panic("jwa: RegisterKeyManagementAlgorithm of unknown algorithm")
	}
	if g != nil {
		panic("jwa: RegisterKeyManagementAlgorithm of already registered algorithm")
	}
	keyManagementAlgorithms[alg] = f
}

func (alg KeyManagementAlgorithm) KeyAlgorithm() KeyAlgorithm {
	return KeyAlgorithm(alg)
}

func (alg KeyManagementAlgorithm) New() keymanage.Algorithm {
	f := keyManagementAlgorithms[alg]
	if f == nil {
		panic("jwa: requested key management algorithm " + alg.String() + " is not available")
	}
	return f()
}

func (alg KeyManagementAlgorithm) Available() bool {
	f := keyManagementAlgorithms[alg]
	return f != nil
}

func (alg KeyManagementAlgorithm) String() string {
	if alg == KeyManagementAlgorithmUnknown {
		return "(unknown)"
	}
	return string(alg)
}

// KeyAlgorithm may be either SignatureAlgorithm or KeyManagementAlgorithm.
// It is a workaround for jwk.Key being able to contain different
// types of algorithms in its `alg` field.
type KeyAlgorithm string

// EncryptionAlgorithm an algorithm for content encryption
// defined in RFC7518 5. Cryptographic Algorithms for Content Encryption.
type EncryptionAlgorithm string

const (
	// A128CBC_HS256 is AES_128_CBC_HMAC_SHA_256 authenticated encryption
	// algorithm, as defined in RFC 7518 Section 5.2.3.
	// import github.com/shogo82148/goat/jwa/acbc
	A128CBC_HS256 EncryptionAlgorithm = "A128CBC-HS256"

	// A192CBC_HS384 is AES_192_CBC_HMAC_SHA_384 authenticated encryption
	// algorithm, as defined in RFC 7518 Section 5.2.4.
	// import github.com/shogo82148/goat/jwa/acbc
	A192CBC_HS384 EncryptionAlgorithm = "A192CBC-HS384"

	// A256CBC_HS512 is AES_256_CBC_HMAC_SHA_512 authenticated encryption
	// algorithm, as defined in RFC 7518 Section 5.2.5.
	// import github.com/shogo82148/goat/jwa/acbc
	A256CBC_HS512 EncryptionAlgorithm = "A256CBC-HS512"

	// A128GCM is AES GCM using 128-bit key.
	// import github.com/shogo82148/goat/jwa/agcm
	A128GCM EncryptionAlgorithm = "A128GCM"

	// A192GCM is AES GCM using 192-bit key.
	// import github.com/shogo82148/goat/jwa/agcm
	A192GCM EncryptionAlgorithm = "A192GCM"

	// A256GCM is AES GCM using 256-bit key.
	// import github.com/shogo82148/goat/jwa/agcm
	A256GCM EncryptionAlgorithm = "A256GCM"
)

var encryptionAlgorithm = map[EncryptionAlgorithm]func() enc.Algorithm{
	A128CBC_HS256: nil,
	A192CBC_HS384: nil,
	A256CBC_HS512: nil,
	A128GCM:       nil,
	A192GCM:       nil,
	A256GCM:       nil,
}

func RegisterEncryptionAlgorithm(alg EncryptionAlgorithm, f func() enc.Algorithm) {
	g, ok := encryptionAlgorithm[alg]
	if !ok {
		panic("jwa: RegisterKeyManagementAlgorithm of unknown algorithm")
	}
	if g != nil {
		panic("jwa: RegisterKeyManagementAlgorithm of already registered algorithm")
	}
	encryptionAlgorithm[alg] = f
}

func (enc EncryptionAlgorithm) String() string {
	return string(enc)
}

func (enc EncryptionAlgorithm) New() enc.Algorithm {
	f := encryptionAlgorithm[enc]
	if f == nil {
		panic("jwa: requested content encryption algorithm " + enc.String() + " is not available")
	}
	return f()
}

func (enc EncryptionAlgorithm) Available() bool {
	f := encryptionAlgorithm[enc]
	return f != nil
}

// KeyType is a key type defined in the IANA "JSON Web Key Types".
type KeyType string

const (
	KeyTypeUnknown KeyType = ""

	// EC is Elliptic Curve.
	EC KeyType = "EC"

	// RSA is RSA.
	RSA KeyType = "RSA"

	// OKP is Octet string key pairs
	// defined in RFC8037 Section 2 Key Type "OKP".
	OKP KeyType = "OKP"

	// Oct is Octet sequence (used to represent symmetric keys).
	Oct KeyType = "oct"
)

func (kyt KeyType) String() string {
	if kyt == KeyTypeUnknown {
		return "(unknown)"
	}
	return string(kyt)
}

// EllipticCurve is an EllipticCurve defined in the IANA "JSON Web Key Elliptic Curve".
type EllipticCurve string

const (
	// P256 is a Curve which implements NIST P-256.
	P256 EllipticCurve = "P-256"

	// P384 is a Curve which implements NIST P-384.
	P384 EllipticCurve = "P-364"

	// P521 is a Curve which implements NIST P-521.
	P521 EllipticCurve = "P-521"

	// Ed25519 is Ed25519 signature algorithm key pairs.
	Ed25519 EllipticCurve = "Ed25519"

	// Ed448 is Ed448 signature algorithm key pairs.
	Ed448 EllipticCurve = "Ed448"

	// X25519 is X25519 function key pairs
	X25519 EllipticCurve = "X25519"

	// X448 is X448 function key pairs.
	X448 EllipticCurve = "X448"

	// secp256k1 is SECG secp256k1 curve.
	Secp256k1 EllipticCurve = "secp256k1"
)

func (crv EllipticCurve) String() string {
	return string(crv)
}

type CompressionAlgorithm string

const (
	CompressionAlgorithmUnknown CompressionAlgorithm = ""

	// DEF is compression with the DEFLATE [RFC1951] algorithm.
	DEF CompressionAlgorithm = "DEF"
)

func (zip CompressionAlgorithm) String() string {
	return string(zip)
}

// JSON Web Signature and Encryption Header Parameters
// https://www.iana.org/assignments/jose/jose.xhtml
const (
	AlgorithmKey                    = "alg"
	EncryptionAlgorithmKey          = "enc"
	CompressionAlgorithmKey         = "zip"
	JWKSetURLKey                    = "jku"
	JSONWebKey                      = "jwk"
	KeyIDKey                        = "kid"
	X509URLKey                      = "x5u"
	X509CertificateChainKey         = "x5c"
	X509CertificateSHA1Thumbprint   = "x5t"
	X509CertificateSHA256Thumbprint = "x5t#S256"
	TypeKey                         = "typ"
	ContentTypeKey                  = "cty"
	CriticalKey                     = "crit"
	EphemeralPublicKeyKey           = "epk"
	AgreementPartyUInfoKey          = "apu"
	AgreementPartyVInfoKey          = "apv"
	InitializationVectorKey         = "iv"
	AuthenticationTagKey            = "tag"
	PBES2SaltInputKey               = "p2s"
	PBES2CountKey                   = "p2c"
	IssuerKey                       = "iss"
	SubjectKey                      = "sub"
	AudienceKey                     = "aud"
	Base64URLEncodePayloadKey       = "b64"
	PASSporTExtensionIdentifierKey  = "ppt"
	URLKey                          = "url"
	NonceKey                        = "nonce"
)
