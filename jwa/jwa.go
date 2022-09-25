// Package jwa implements RFC7518.
package jwa

import "github.com/shogo82148/goat/sig"

// SignatureAlgorithm is an algorithm for JSON Web Signature (JWS)
// defined in the IANA "JSON Web Signature and Encryption Algorithms".
type SignatureAlgorithm string

const (
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
		panic("jwa: requested signature algorithm " + string(alg) + " is not available")
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
	// RSA1_5 is RSAES-PKCS1-v1_5.
	RSA1_5 KeyManagementAlgorithm = "RSA1_5"

	// RSA_OAEP is RSAES OAEP using.
	RSA_OAEP KeyManagementAlgorithm = "RSA-OAEP"

	// RSA_OAEP_256 is RSAES OAEP using SHA-256 and MGF1 with SHA-256.
	RSA_OAEP_256 KeyManagementAlgorithm = "RSA-OAEP-256"

	// A128KW is AES Key Wrap with default initial value using 128-bit key.
	A128KW KeyManagementAlgorithm = "A128KW"

	// A192KW is AES Key Wrap with default initial value using 192-bit key.
	A192KW KeyManagementAlgorithm = "A192KW"

	// A256KW is AES Key Wrap with default initial value using 256-bit key.
	A256KW KeyManagementAlgorithm = "A256KW"

	// Direct is direct use of a shared symmetric key as the CEK.
	Direct KeyManagementAlgorithm = "dir"

	// ECDH_ES is Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF.
	ECDH_ES KeyManagementAlgorithm = "ECDH-ES"

	// ECDH_ES_A128KW is ECDH-ES using Concat KDF and CEK wrapped with "A128K".
	ECDH_ES_A128KW KeyManagementAlgorithm = "ECDH-ES+A128KW"

	// ECDH_ES_A192KW is ECDH-ES using Concat KDF and CEK wrapped with "A192K".
	ECDH_ES_A192KW KeyManagementAlgorithm = "ECDH-ES+A192KW"

	// ECDH_ES_A256KW is ECDH-ES using Concat KDF and CEK wrapped with "A256K".
	ECDH_ES_A256KW KeyManagementAlgorithm = "ECDH-ES+A256KW"

	// A128GCMKW is Key wrapping with AES GCM using 128-bit key.
	A128GCMKW KeyManagementAlgorithm = "A128GCMKW"

	// A196GCMKW is Key wrapping with AES GCM using 196-bit key.
	A192GCMKW KeyManagementAlgorithm = "A192GCMKW"

	// A256GCMKW is Key wrapping with AES GCM using 256-bit key.
	A256GCMKW KeyManagementAlgorithm = "A256GCMKW"

	// PBES2_HS256_A128KW is PBES2 with HMAC SHA-256 and "A128KW" wrapping.
	PBES2_HS256_A128KW KeyManagementAlgorithm = "PBES2-HS256+A128KW"

	// PBES2_HS384_A192KW is PBES2 with HMAC SHA-384 and "A192KW" wrapping.
	PBES2_HS384_A192KW KeyManagementAlgorithm = "PBES2-HS384+A192KW"

	// PBES2_HS512_A256KW is PBES2 with HMAC SHA-512 and "A256KW" wrapping.
	PBES2_HS512_A256KW KeyManagementAlgorithm = "PBES2-HS512+A256KW"
)

func (alg KeyManagementAlgorithm) KeyAlgorithm() KeyAlgorithm {
	return KeyAlgorithm(alg)
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
	A128CBC_HS256 EncryptionAlgorithm = "A128CBC-HS256"

	// A192CBC_HS384 is AES_192_CBC_HMAC_SHA_384 authenticated encryption
	// algorithm, as defined in RFC 7518 Section 5.2.4.
	A192CBC_HS384 EncryptionAlgorithm = "A192CBC-HS384"

	// A256CBC_HS512 is AES_256_CBC_HMAC_SHA_512 authenticated encryption
	// algorithm, as defined in RFC 7518 Section 5.2.5.
	A256CBC_HS512 EncryptionAlgorithm = "A256CBC-HS512"

	// A128GCM is AES GCM using 128-bit key.
	A128GCM EncryptionAlgorithm = "A128GCM"

	// A192GCM is AES GCM using 192-bit key.
	A192GCM EncryptionAlgorithm = "A192GCM"

	// A256GCM is AES GCM using 256-bit key.
	A256GCM EncryptionAlgorithm = "A256GCM"
)

// KeyType is a key type defined in the IANA "JSON Web Key Types".
type KeyType string

const (
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
