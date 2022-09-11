// Package jwa implements RFC7518.
package jwa

// SignAlgorithm is an algorithm for JSON Web Signature (JWS).
type SignAlgorithm string

const (
	// HS256 is HMAC using SHA-256.
	HS256 SignAlgorithm = "HS256"

	// HS384 is HMAC using SHA-384.
	HS384 SignAlgorithm = "HS384"

	// HS512 is HMAC using SHA-512.
	HS512 SignAlgorithm = "HS512"

	// RS256 is RSASSA-PKCS1-v1_5 using SHA-256.
	RS256 SignAlgorithm = "RS256"

	// RS384 is RSASSA-PKCS1-v1_5 using SHA-384.
	RS384 SignAlgorithm = "RS384"

	// RS512 is RSASSA-PKCS1-v1_5 using SHA-512.
	RS512 SignAlgorithm = "RS512"

	// ES256 is ECDSA using P-256 and SHA-256.
	ES256 SignAlgorithm = "ES256"

	// ES384 is ECDSA using P-384 and SHA-384.
	ES384 SignAlgorithm = "ES384"

	// ES512 is ECDSA using P-521 and SHA-512.
	ES512 SignAlgorithm = "ES512"

	// PS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
	PS256 SignAlgorithm = "PS256"

	// PS384 is RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
	PS384 SignAlgorithm = "PS384"

	// PS512 is RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
	PS512 SignAlgorithm = "PS512"

	// None is no digital signature or MAC performed.
	None SignAlgorithm = "none"
)

// EncryptAlgorithm is an algorithm for JSON Web Encryption (JWE).
type EncryptAlgorithm string

const (
	// RSA1_5 is RSAES-PKCS1-v1_5.
	RSA1_5 EncryptAlgorithm = "RSA1_5"

	// RSA_OAEP is RSAES OAEP using.
	RSA_OAEP EncryptAlgorithm = "RSA-OAEP"

	// RSA_OAEP_256 is RSAES OAEP using SHA-256 and MGF1 with SHA-256.
	RSA_OAEP_256 EncryptAlgorithm = "RSA-OAEP-256"

	// A128KW is AES Key Wrap with default initial value using 128-bit key.
	A128KW EncryptAlgorithm = "A128KW"

	// A192KW is AES Key Wrap with default initial value using 192-bit key.
	A192KW EncryptAlgorithm = "A192KW"

	// A256KW is AES Key Wrap with default initial value using 256-bit key.
	A256KW EncryptAlgorithm = "A256KW"

	// Direct is direct use of a shared symmetric key as the CEK.
	Direct EncryptAlgorithm = "dir"

	// ECDH_ES is Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF.
	ECDH_ES EncryptAlgorithm = "ECDH-ES"

	// ECDH_ES_A128KW is ECDH-ES using Concat KDF and CEK wrapped with "A128K".
	ECDH_ES_A128KW EncryptAlgorithm = "ECDH-ES+A128KW"

	// ECDH_ES_A192KW is ECDH-ES using Concat KDF and CEK wrapped with "A192K".
	ECDH_ES_A192KW EncryptAlgorithm = "ECDH-ES+A192KW"

	// ECDH_ES_A256KW is ECDH-ES using Concat KDF and CEK wrapped with "A256K".
	ECDH_ES_A256KW EncryptAlgorithm = "ECDH-ES+A256KW"

	// A128GCMKW is Key wrapping with AES GCM using 128-bit key.
	A128GCMKW EncryptAlgorithm = "A128GCMKW"

	// A196GCMKW is Key wrapping with AES GCM using 196-bit key.
	A192GCMKW EncryptAlgorithm = "A192GCMKW"

	// A256GCMKW is Key wrapping with AES GCM using 256-bit key.
	A256GCMKW EncryptAlgorithm = "A256GCMKW"

	// PBES2_HS256_A128KW is PBES2 with HMAC SHA-256 and "A128KW" wrapping.
	PBES2_HS256_A128KW EncryptAlgorithm = "PBES2-HS256+A128KW"

	// PBES2_HS384_A192KW is PBES2 with HMAC SHA-384 and "A192KW" wrapping.
	PBES2_HS384_A192KW EncryptAlgorithm = "PBES2-HS384+A192KW"

	// PBES2_HS512_A256KW is PBES2 with HMAC SHA-512 and "A256KW" wrapping.
	PBES2_HS512_A256KW EncryptAlgorithm = "PBES2-HS512+A256KW"
)
