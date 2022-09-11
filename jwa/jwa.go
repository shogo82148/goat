// Package jwa implements RFC7518.
package jwa

// SignatureAlgorithm is an algorithm for JSON Web Signature (JWS)
// defined in RFC8518 Section 3 Cryptographic Algorithms for Digital Signatures and MACs.
type SignatureAlgorithm string

const (
	// HS256 is HMAC using SHA-256.
	HS256 SignatureAlgorithm = "HS256"

	// HS384 is HMAC using SHA-384.
	HS384 SignatureAlgorithm = "HS384"

	// HS512 is HMAC using SHA-512.
	HS512 SignatureAlgorithm = "HS512"

	// RS256 is RSASSA-PKCS1-v1_5 using SHA-256.
	RS256 SignatureAlgorithm = "RS256"

	// RS384 is RSASSA-PKCS1-v1_5 using SHA-384.
	RS384 SignatureAlgorithm = "RS384"

	// RS512 is RSASSA-PKCS1-v1_5 using SHA-512.
	RS512 SignatureAlgorithm = "RS512"

	// ES256 is ECDSA using P-256 and SHA-256.
	ES256 SignatureAlgorithm = "ES256"

	// ES384 is ECDSA using P-384 and SHA-384.
	ES384 SignatureAlgorithm = "ES384"

	// ES512 is ECDSA using P-521 and SHA-512.
	ES512 SignatureAlgorithm = "ES512"

	// PS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
	PS256 SignatureAlgorithm = "PS256"

	// PS384 is RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
	PS384 SignatureAlgorithm = "PS384"

	// PS512 is RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
	PS512 SignatureAlgorithm = "PS512"

	// None is no digital signature or MAC performed.
	None SignatureAlgorithm = "none"
)

// KeyManagementAlgorithm is an algorithm for JSON Web Encryption (JWE)
// defined in RFC7518 4. Cryptographic Algorithms for Key Management
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

// KeyAlgorithm may be either SignatureAlgorithm or KeyManagementAlgorithm.
// It is a workaround for jwk.Key being able to contain different
// types of algorithms in its `alg` field.
type KeyAlgorithm string

// SignatureAlgorithm casts alg to SignatureAlgorithm.
func (alg KeyAlgorithm) SignatureAlgorithm() SignatureAlgorithm {
	return SignatureAlgorithm(alg)
}

// KeyManagementAlgorithm cast alg to KeyManagementAlgorithm.
func (alg KeyAlgorithm) KeyManagementAlgorithm() KeyManagementAlgorithm {
	return KeyManagementAlgorithm(alg)
}

// ContentEncryptionAlgorithm an algorithm for content encryption
// defined in RFC7518 5. Cryptographic Algorithms for Content Encryption.
type ContentEncryptionAlgorithm string

// KeyType is a key type defined in RFC7518 Section 6 Cryptographic Algorithms for Keys.
type KeyType string

const (
	// EC is Elliptic Curve.
	EC = "EC"

	// RSA is RSA.
	RSA = "RSA"

	// OKP is Octet string key pairs
	// defined in RFC8037 Section 2 Key Type "OKP".
	OKP = "OKP"

	// Oct is Octet sequence (used to represent symmetric keys).
	Oct = "oct"
)
