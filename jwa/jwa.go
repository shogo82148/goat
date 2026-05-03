// Package jwa implements cryptographic algorithms defined in RFC 7518.
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
	// HS256 is HMAC using SHA-256.
	// import github.com/shogo82148/goat/jwa/hs
	//
	// Deprecated: use [SignatureAlgorithmHS256] instead of HS256.
	//go:fix inline
	HS256 = SignatureAlgorithmHS256

	// HS384 is HMAC using SHA-384.
	// import github.com/shogo82148/goat/jwa/hs
	//
	// Deprecated: use [SignatureAlgorithmHS384] instead of HS384.
	//go:fix inline
	HS384 = SignatureAlgorithmHS384

	// HS512 is HMAC using SHA-512.
	// import github.com/shogo82148/goat/jwa/hs
	//
	// Deprecated: use [SignatureAlgorithmHS512] instead of HS512.
	//go:fix inline
	HS512 = SignatureAlgorithmHS512

	// RS256 is RSASSA-PKCS1-v1_5 using SHA-256.
	// import github.com/shogo82148/goat/jwa/rs
	//
	// Deprecated: use [SignatureAlgorithmRS256] instead of RS256.
	//go:fix inline
	RS256 = SignatureAlgorithmRS256

	// RS384 is RSASSA-PKCS1-v1_5 using SHA-384.
	// import github.com/shogo82148/goat/jwa/rs
	//
	// Deprecated: use [SignatureAlgorithmRS384] instead of RS384.
	//go:fix inline
	RS384 = SignatureAlgorithmRS384

	// RS512 is RSASSA-PKCS1-v1_5 using SHA-512.
	// import github.com/shogo82148/goat/jwa/rs
	//
	// Deprecated: use [SignatureAlgorithmRS512] instead of RS512.
	//go:fix inline
	RS512 = SignatureAlgorithmRS512

	// ES256 is ECDSA using P-256 and SHA-256.
	// import github.com/shogo82148/goat/jwa/es
	//
	// Deprecated: use [SignatureAlgorithmES256] instead of ES256.
	//go:fix inline
	ES256 = SignatureAlgorithmES256

	// ES384 is ECDSA using P-384 and SHA-384.
	// import github.com/shogo82148/goat/jwa/es
	//
	// Deprecated: use [SignatureAlgorithmES384] instead of ES384.
	//go:fix inline
	ES384 = SignatureAlgorithmES384

	// ES512 is ECDSA using P-521 and SHA-512.
	// import github.com/shogo82148/goat/jwa/es
	//
	// Deprecated: use [SignatureAlgorithmES512] instead of ES512.
	//go:fix inline
	ES512 = SignatureAlgorithmES512

	// PS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
	// import github.com/shogo82148/goat/jwa/ps
	//
	// Deprecated: use [SignatureAlgorithmPS256] instead of PS256.
	//go:fix inline
	PS256 = SignatureAlgorithmPS256

	// PS384 is RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
	// import github.com/shogo82148/goat/jwa/ps
	//
	// Deprecated: use [SignatureAlgorithmPS384] instead of PS384.
	//go:fix inline
	PS384 = SignatureAlgorithmPS384

	// PS512 is RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
	// import github.com/shogo82148/goat/jwa/ps
	//
	// Deprecated: use [SignatureAlgorithmPS512] instead of PS512.
	//go:fix inline
	PS512 = SignatureAlgorithmPS512

	// None is no digital signature or MAC performed.
	// import github.com/shogo82148/goat/jwa/none
	//
	// Deprecated: use [SignatureAlgorithmNone] instead of None.
	//go:fix inline
	None = SignatureAlgorithmNone

	// EdDSA is Edwards-Curve Digital Signature Algorithm.
	// import github.com/shogo82148/goat/jwa/eddsa
	//
	// Deprecated: use [SignatureAlgorithmEd25519] or [SignatureAlgorithmEd448] instead of EdDSA.
	EdDSA = SignatureAlgorithmEdDSA

	// ES256K is ECDSA using secp256k1 curve and SHA-256.
	// import github.com/shogo82148/goat/jwa/es
	//
	// Deprecated: use [SignatureAlgorithmES256K] instead of ES256K.
	//go:fix inline
	ES256K = SignatureAlgorithmES256K
)

const (
	// SignatureAlgorithmUnknown is an unknown signature algorithm.
	SignatureAlgorithmUnknown SignatureAlgorithm = ""

	// SignatureAlgorithmHS256 is HMAC using SHA-256.
	// import github.com/shogo82148/goat/jwa/hs
	SignatureAlgorithmHS256 SignatureAlgorithm = "HS256"

	// SignatureAlgorithmHS384 is HMAC using SHA-384.
	// import github.com/shogo82148/goat/jwa/hs
	SignatureAlgorithmHS384 SignatureAlgorithm = "HS384"

	// SignatureAlgorithmHS512 is HMAC using SHA-512.
	// import github.com/shogo82148/goat/jwa/hs
	SignatureAlgorithmHS512 SignatureAlgorithm = "HS512"

	// SignatureAlgorithmRS256 is RSASSA-PKCS1-v1_5 using SHA-256.
	// import github.com/shogo82148/goat/jwa/rs
	SignatureAlgorithmRS256 SignatureAlgorithm = "RS256"

	// SignatureAlgorithmRS384 is RSASSA-PKCS1-v1_5 using SHA-384.
	// import github.com/shogo82148/goat/jwa/rs
	SignatureAlgorithmRS384 SignatureAlgorithm = "RS384"

	// SignatureAlgorithmRS512 is RSASSA-PKCS1-v1_5 using SHA-512.
	// import github.com/shogo82148/goat/jwa/rs
	SignatureAlgorithmRS512 SignatureAlgorithm = "RS512"

	// SignatureAlgorithmES256 is ECDSA using P-256 and SHA-256.
	// import github.com/shogo82148/goat/jwa/es
	SignatureAlgorithmES256 SignatureAlgorithm = "ES256"

	// SignatureAlgorithmES384 is ECDSA using P-384 and SHA-384.
	// import github.com/shogo82148/goat/jwa/es
	SignatureAlgorithmES384 SignatureAlgorithm = "ES384"

	// SignatureAlgorithmES512 is ECDSA using P-521 and SHA-512.
	// import github.com/shogo82148/goat/jwa/es
	SignatureAlgorithmES512 SignatureAlgorithm = "ES512"

	// SignatureAlgorithmPS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
	// import github.com/shogo82148/goat/jwa/ps
	SignatureAlgorithmPS256 SignatureAlgorithm = "PS256"

	// SignatureAlgorithmPS384 is RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
	// import github.com/shogo82148/goat/jwa/ps
	SignatureAlgorithmPS384 SignatureAlgorithm = "PS384"

	// SignatureAlgorithmPS512 is RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
	// import github.com/shogo82148/goat/jwa/ps
	SignatureAlgorithmPS512 SignatureAlgorithm = "PS512"

	// SignatureAlgorithmNone is no digital signature or MAC performed.
	// import github.com/shogo82148/goat/jwa/none
	SignatureAlgorithmNone SignatureAlgorithm = "none"

	// SignatureAlgorithmEdDSA is Edwards-Curve Digital Signature Algorithm.
	// import github.com/shogo82148/goat/jwa/eddsa
	//
	// Deprecated: use [SignatureAlgorithmEd25519] or [SignatureAlgorithmEd448] instead of EdDSA.
	SignatureAlgorithmEdDSA SignatureAlgorithm = "EdDSA"

	// SignatureAlgorithmEd25519 is Ed25519 signature algorithm.
	// import github.com/shogo82148/goat/jwa/ed25519
	SignatureAlgorithmEd25519 SignatureAlgorithm = "Ed25519"

	// SignatureAlgorithmEd448 is Ed448 signature algorithm.
	// import github.com/shogo82148/goat/jwa/ed448
	SignatureAlgorithmEd448 SignatureAlgorithm = "Ed448"

	// SignatureAlgorithmES256K is ECDSA using secp256k1 curve and SHA-256.
	// import github.com/shogo82148/goat/jwa/es
	SignatureAlgorithmES256K SignatureAlgorithm = "ES256K"
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
	SignatureAlgorithmHS256:   nil,
	SignatureAlgorithmHS384:   nil,
	SignatureAlgorithmHS512:   nil,
	SignatureAlgorithmRS256:   nil,
	SignatureAlgorithmRS384:   nil,
	SignatureAlgorithmRS512:   nil,
	SignatureAlgorithmES256:   nil,
	SignatureAlgorithmES384:   nil,
	SignatureAlgorithmES512:   nil,
	SignatureAlgorithmPS256:   nil,
	SignatureAlgorithmPS384:   nil,
	SignatureAlgorithmPS512:   nil,
	SignatureAlgorithmNone:    nil,
	SignatureAlgorithmEdDSA:   nil,
	SignatureAlgorithmEd25519: nil,
	SignatureAlgorithmEd448:   nil,
	SignatureAlgorithmES256K:  nil,
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
	// import github.com/shogo82148/goat/jwa/rsapkcs1v15
	//
	// Deprecated: use [KeyManagementAlgorithmRSA1_5] instead of RSA1_5.
	//go:fix inline
	RSA1_5 = KeyManagementAlgorithmRSA1_5

	// RSA_OAEP is RSAES OAEP.
	// import github.com/shogo82148/goat/jwa/rsapoaep
	//
	// Deprecated: use [KeyManagementAlgorithmRSA_OAEP] instead of RSA_OAEP.
	//go:fix inline
	RSA_OAEP = KeyManagementAlgorithmRSA_OAEP

	// RSA_OAEP_256 is RSAES OAEP using SHA-256 and MGF1 with SHA-256.
	// import github.com/shogo82148/goat/jwa/rsapoaep
	//
	// Deprecated: use [KeyManagementAlgorithmRSA_OAEP_256] instead of RSA_OAEP_256.
	//go:fix inline
	RSA_OAEP_256 = KeyManagementAlgorithmRSA_OAEP_256

	// A128KW is AES Key Wrap with default initial value using 128-bit key.
	// import github.com/shogo82148/goat/jwa/akw
	//
	// Deprecated: use [KeyManagementAlgorithmA128KW] instead of A128KW.
	//go:fix inline
	A128KW = KeyManagementAlgorithmA128KW

	// A192KW is AES Key Wrap with default initial value using 192-bit key.
	// import github.com/shogo82148/goat/jwa/akw
	//
	// Deprecated: use [KeyManagementAlgorithmA192KW] instead of A192KW.
	//go:fix inline
	A192KW = KeyManagementAlgorithmA192KW

	// A256KW is AES Key Wrap with default initial value using 256-bit key.
	// import github.com/shogo82148/goat/jwa/akw
	//
	// Deprecated: use [KeyManagementAlgorithmA256KW] instead of A256KW.
	//go:fix inline
	A256KW = KeyManagementAlgorithmA256KW

	// Direct is direct use of a shared symmetric key as the CEK.
	// import github.com/shogo82148/goat/jwa/dir
	//
	// Deprecated: use [KeyManagementAlgorithmDirect] instead of Direct.
	//go:fix inline
	Direct = KeyManagementAlgorithmDirect

	// ECDH_ES is Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF.
	// import github.com/shogo82148/goat/jwa/ecdhes
	//
	// Deprecated: use [KeyManagementAlgorithmECDH_ES] instead of ECDH_ES.
	//go:fix inline
	ECDH_ES = KeyManagementAlgorithmECDH_ES

	// ECDH_ES_A128KW is ECDH-ES using Concat KDF and CEK wrapped with "A128KW".
	// import github.com/shogo82148/goat/jwa/ecdhes
	//
	// Deprecated: use [KeyManagementAlgorithmECDH_ES_A128KW] instead of ECDH_ES_A128KW.
	//go:fix inline
	ECDH_ES_A128KW = KeyManagementAlgorithmECDH_ES_A128KW

	// ECDH_ES_A192KW is ECDH-ES using Concat KDF and CEK wrapped with "A192KW".
	// import github.com/shogo82148/goat/jwa/ecdhes
	//
	// Deprecated: use [KeyManagementAlgorithmECDH_ES_A192KW] instead of ECDH_ES_A192KW.
	//go:fix inline
	ECDH_ES_A192KW = KeyManagementAlgorithmECDH_ES_A192KW

	// ECDH_ES_A256KW is ECDH-ES using Concat KDF and CEK wrapped with "A256KW".
	// import github.com/shogo82148/goat/jwa/ecdhes
	//
	// Deprecated: use [KeyManagementAlgorithmECDH_ES_A256KW] instead of ECDH_ES_A256KW.
	//go:fix inline
	ECDH_ES_A256KW = KeyManagementAlgorithmECDH_ES_A256KW

	// A128GCMKW is Key wrapping with AES GCM using 128-bit key.
	// import github.com/shogo82148/goat/jwa/agcmkw
	//
	// Deprecated: use [KeyManagementAlgorithmA128GCMKW] instead of A128GCMKW.
	//go:fix inline
	A128GCMKW = KeyManagementAlgorithmA128GCMKW

	// A192GCMKW is Key wrapping with AES GCM using 192-bit key.
	// import github.com/shogo82148/goat/jwa/agcmkw
	//
	// Deprecated: use [KeyManagementAlgorithmA192GCMKW] instead of A192GCMKW.
	//go:fix inline
	A192GCMKW = KeyManagementAlgorithmA192GCMKW

	// A256GCMKW is Key wrapping with AES GCM using 256-bit key.
	// import github.com/shogo82148/goat/jwa/agcmkw
	//
	// Deprecated: use [KeyManagementAlgorithmA256GCMKW] instead of A256GCMKW.
	//go:fix inline
	A256GCMKW = KeyManagementAlgorithmA256GCMKW

	// PBES2_HS256_A128KW is PBES2 with HMAC SHA-256 and "A128KW" wrapping.
	// import github.com/shogo82148/goat/jwa/pbes2
	//
	// Deprecated: use [KeyManagementAlgorithmPBES2_HS256_A128KW] instead of PBES2_HS256_A128KW.
	//go:fix inline
	PBES2_HS256_A128KW = KeyManagementAlgorithmPBES2_HS256_A128KW

	// PBES2_HS384_A192KW is PBES2 with HMAC SHA-384 and "A192KW" wrapping.
	// import github.com/shogo82148/goat/jwa/pbes2
	//
	// Deprecated: use [KeyManagementAlgorithmPBES2_HS384_A192KW] instead of PBES2_HS384_A192KW.
	//go:fix inline
	PBES2_HS384_A192KW = KeyManagementAlgorithmPBES2_HS384_A192KW

	// PBES2_HS512_A256KW is PBES2 with HMAC SHA-512 and "A256KW" wrapping.
	// import github.com/shogo82148/goat/jwa/pbes2
	//
	// Deprecated: use [KeyManagementAlgorithmPBES2_HS512_A256KW] instead of PBES2_HS512_A256KW.
	//go:fix inline
	PBES2_HS512_A256KW = KeyManagementAlgorithmPBES2_HS512_A256KW
)

const (
	KeyManagementAlgorithmUnknown KeyManagementAlgorithm = ""

	// KeyManagementAlgorithmRSA1_5 is RSAES-PKCS1-v1_5.
	// import github.com/shogo82148/goat/jwa/rsapkcs1v15
	//
	// Deprecated: RSAES-PKCS1-v1_5 is not recommended, use [KeyManagementAlgorithmRSA_OAEP] instead.
	KeyManagementAlgorithmRSA1_5 KeyManagementAlgorithm = "RSA1_5"

	// KeyManagementAlgorithmRSA_OAEP is RSAES OAEP.
	// import github.com/shogo82148/goat/jwa/rsapoaep
	KeyManagementAlgorithmRSA_OAEP KeyManagementAlgorithm = "RSA-OAEP"

	// KeyManagementAlgorithmRSA_OAEP_256 is RSAES OAEP using SHA-256 and MGF1 with SHA-256.
	// import github.com/shogo82148/goat/jwa/rsapoaep
	KeyManagementAlgorithmRSA_OAEP_256 KeyManagementAlgorithm = "RSA-OAEP-256"

	// KeyManagementAlgorithmA128KW is AES Key Wrap with default initial value using 128-bit key.
	// import github.com/shogo82148/goat/jwa/akw
	KeyManagementAlgorithmA128KW KeyManagementAlgorithm = "A128KW"

	// KeyManagementAlgorithmA192KW is AES Key Wrap with default initial value using 192-bit key.
	// import github.com/shogo82148/goat/jwa/akw
	KeyManagementAlgorithmA192KW KeyManagementAlgorithm = "A192KW"

	// KeyManagementAlgorithmA256KW is AES Key Wrap with default initial value using 256-bit key.
	// import github.com/shogo82148/goat/jwa/akw
	KeyManagementAlgorithmA256KW KeyManagementAlgorithm = "A256KW"

	// KeyManagementAlgorithmDirect is direct use of a shared symmetric key as the CEK.
	// import github.com/shogo82148/goat/jwa/dir
	KeyManagementAlgorithmDirect KeyManagementAlgorithm = "dir"

	// KeyManagementAlgorithmECDH_ES is Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF.
	// import github.com/shogo82148/goat/jwa/ecdhes
	KeyManagementAlgorithmECDH_ES KeyManagementAlgorithm = "ECDH-ES"

	// KeyManagementAlgorithmECDH_ES_A128KW is ECDH-ES using Concat KDF and CEK wrapped with "A128KW".
	// import github.com/shogo82148/goat/jwa/ecdhes
	KeyManagementAlgorithmECDH_ES_A128KW KeyManagementAlgorithm = "ECDH-ES+A128KW"

	// KeyManagementAlgorithmECDH_ES_A192KW is ECDH-ES using Concat KDF and CEK wrapped with "A192KW".
	// import github.com/shogo82148/goat/jwa/ecdhes
	KeyManagementAlgorithmECDH_ES_A192KW KeyManagementAlgorithm = "ECDH-ES+A192KW"

	// KeyManagementAlgorithmECDH_ES_A256KW is ECDH-ES using Concat KDF and CEK wrapped with "A256KW".
	// import github.com/shogo82148/goat/jwa/ecdhes
	KeyManagementAlgorithmECDH_ES_A256KW KeyManagementAlgorithm = "ECDH-ES+A256KW"

	// KeyManagementAlgorithmA128GCMKW is Key wrapping with AES GCM using 128-bit key.
	// import github.com/shogo82148/goat/jwa/agcmkw
	KeyManagementAlgorithmA128GCMKW KeyManagementAlgorithm = "A128GCMKW"

	// KeyManagementAlgorithmA192GCMKW is Key wrapping with AES GCM using 192-bit key.
	// import github.com/shogo82148/goat/jwa/agcmkw
	KeyManagementAlgorithmA192GCMKW KeyManagementAlgorithm = "A192GCMKW"

	// KeyManagementAlgorithmA256GCMKW is Key wrapping with AES GCM using 256-bit key.
	// import github.com/shogo82148/goat/jwa/agcmkw
	KeyManagementAlgorithmA256GCMKW KeyManagementAlgorithm = "A256GCMKW"

	// KeyManagementAlgorithmPBES2_HS256_A128KW is PBES2 with HMAC SHA-256 and "A128KW" wrapping.
	// import github.com/shogo82148/goat/jwa/pbes2
	KeyManagementAlgorithmPBES2_HS256_A128KW KeyManagementAlgorithm = "PBES2-HS256+A128KW"

	// KeyManagementAlgorithmPBES2_HS384_A192KW is PBES2 with HMAC SHA-384 and "A192KW" wrapping.
	// import github.com/shogo82148/goat/jwa/pbes2
	KeyManagementAlgorithmPBES2_HS384_A192KW KeyManagementAlgorithm = "PBES2-HS384+A192KW"

	// KeyManagementAlgorithmPBES2_HS512_A256KW is PBES2 with HMAC SHA-512 and "A256KW" wrapping.
	// import github.com/shogo82148/goat/jwa/pbes2
	KeyManagementAlgorithmPBES2_HS512_A256KW KeyManagementAlgorithm = "PBES2-HS512+A256KW"

	// KeyManagementAlgorithmMLKEM768 is ML-KEM-768.
	// import github.com/shogo82148/goat/jwa/mlkem
	KeyManagementAlgorithmMLKEM768 KeyManagementAlgorithm = "ML-KEM-768"

	// KeyManagementAlgorithmMLKEM1024 is ML-KEM-1024.
	// import github.com/shogo82148/goat/jwa/mlkem
	KeyManagementAlgorithmMLKEM1024 KeyManagementAlgorithm = "ML-KEM-1024"

	// KeyManagementAlgorithmMLKEM768_AES192KW is ML-KEM-768 + AES192KW.
	// import github.com/shogo82148/goat/jwa/mlkem
	KeyManagementAlgorithmMLKEM768_AES192KW KeyManagementAlgorithm = "ML-KEM-768+AES192KW"

	// KeyManagementAlgorithmMLKEM1024_AES256KW is ML-KEM-1024 + AES256KW.
	// import github.com/shogo82148/goat/jwa/mlkem
	KeyManagementAlgorithmMLKEM1024_AES256KW KeyManagementAlgorithm = "ML-KEM-1024+AES256KW"
)

var keyManagementAlgorithms = map[KeyManagementAlgorithm]func() keymanage.Algorithm{
	KeyManagementAlgorithmRSA1_5:             nil,
	KeyManagementAlgorithmRSA_OAEP:           nil,
	KeyManagementAlgorithmRSA_OAEP_256:       nil,
	KeyManagementAlgorithmA128KW:             nil,
	KeyManagementAlgorithmA192KW:             nil,
	KeyManagementAlgorithmA256KW:             nil,
	KeyManagementAlgorithmDirect:             nil,
	KeyManagementAlgorithmECDH_ES:            nil,
	KeyManagementAlgorithmECDH_ES_A128KW:     nil,
	KeyManagementAlgorithmECDH_ES_A192KW:     nil,
	KeyManagementAlgorithmECDH_ES_A256KW:     nil,
	KeyManagementAlgorithmA128GCMKW:          nil,
	KeyManagementAlgorithmA192GCMKW:          nil,
	KeyManagementAlgorithmA256GCMKW:          nil,
	KeyManagementAlgorithmPBES2_HS256_A128KW: nil,
	KeyManagementAlgorithmPBES2_HS384_A192KW: nil,
	KeyManagementAlgorithmPBES2_HS512_A256KW: nil,
	KeyManagementAlgorithmMLKEM768:           nil,
	KeyManagementAlgorithmMLKEM1024:          nil,
	KeyManagementAlgorithmMLKEM768_AES192KW:  nil,
	KeyManagementAlgorithmMLKEM1024_AES256KW: nil,
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
// defined in RFC 7518 Section.5. Cryptographic Algorithms for Content Encryption.
type EncryptionAlgorithm string

const (
	// A128CBC_HS256 is AES_128_CBC_HMAC_SHA_256 authenticated encryption
	// algorithm, as defined in RFC 7518 Section 5.2.3.
	// import github.com/shogo82148/goat/jwa/acbc
	//
	// Deprecated: use [EncryptionAlgorithmA128CBC_HS256] instead of A128CBC_HS256.
	//go:fix inline
	A128CBC_HS256 = EncryptionAlgorithmA128CBC_HS256

	// A192CBC_HS384 is AES_192_CBC_HMAC_SHA_384 authenticated encryption
	// algorithm, as defined in RFC 7518 Section 5.2.4.
	// import github.com/shogo82148/goat/jwa/acbc
	//
	// Deprecated: use [EncryptionAlgorithmA192CBC_HS384] instead of A192CBC_HS384.
	//go:fix inline
	A192CBC_HS384 = EncryptionAlgorithmA192CBC_HS384

	// A256CBC_HS512 is AES_256_CBC_HMAC_SHA_512 authenticated encryption
	// algorithm, as defined in RFC 7518 Section 5.2.5.
	// import github.com/shogo82148/goat/jwa/acbc
	//
	// Deprecated: use [EncryptionAlgorithmA256CBC_HS512] instead of A256CBC_HS512.
	//go:fix inline
	A256CBC_HS512 = EncryptionAlgorithmA256CBC_HS512

	// A128GCM is AES GCM using 128-bit key.
	// import github.com/shogo82148/goat/jwa/agcm
	//
	// Deprecated: use [EncryptionAlgorithmA128GCM] instead of A128GCM.
	//go:fix inline
	A128GCM = EncryptionAlgorithmA128GCM

	// A192GCM is AES GCM using 192-bit key.
	// import github.com/shogo82148/goat/jwa/agcm
	//
	// Deprecated: use [EncryptionAlgorithmA192GCM] instead of A192GCM.
	//go:fix inline
	A192GCM = EncryptionAlgorithmA192GCM

	// A256GCM is AES GCM using 256-bit key.
	// import github.com/shogo82148/goat/jwa/agcm
	//
	// Deprecated: use [EncryptionAlgorithmA256GCM] instead of A256GCM.
	//go:fix inline
	A256GCM = EncryptionAlgorithmA256GCM
)

const (
	// EncryptionAlgorithmA128CBC_HS256 is AES_128_CBC_HMAC_SHA_256 authenticated encryption
	// algorithm, as defined in RFC 7518 Section 5.2.3.
	// import github.com/shogo82148/goat/jwa/acbc
	EncryptionAlgorithmA128CBC_HS256 EncryptionAlgorithm = "A128CBC-HS256"

	// EncryptionAlgorithmA192CBC_HS384 is AES_192_CBC_HMAC_SHA_384 authenticated encryption
	// algorithm, as defined in RFC 7518 Section 5.2.4.
	// import github.com/shogo82148/goat/jwa/acbc
	EncryptionAlgorithmA192CBC_HS384 EncryptionAlgorithm = "A192CBC-HS384"

	// EncryptionAlgorithmA256CBC_HS512 is AES_256_CBC_HMAC_SHA_512 authenticated encryption
	// algorithm, as defined in RFC 7518 Section 5.2.5.
	// import github.com/shogo82148/goat/jwa/acbc
	EncryptionAlgorithmA256CBC_HS512 EncryptionAlgorithm = "A256CBC-HS512"

	// EncryptionAlgorithmA128GCM is AES GCM using 128-bit key.
	// import github.com/shogo82148/goat/jwa/agcm
	EncryptionAlgorithmA128GCM EncryptionAlgorithm = "A128GCM"

	// EncryptionAlgorithmA192GCM is AES GCM using 192-bit key.
	// import github.com/shogo82148/goat/jwa/agcm
	EncryptionAlgorithmA192GCM EncryptionAlgorithm = "A192GCM"

	// EncryptionAlgorithmA256GCM is AES GCM using 256-bit key.
	// import github.com/shogo82148/goat/jwa/agcm
	EncryptionAlgorithmA256GCM EncryptionAlgorithm = "A256GCM"
)

var encryptionAlgorithm = map[EncryptionAlgorithm]func() enc.Algorithm{
	EncryptionAlgorithmA128CBC_HS256: nil,
	EncryptionAlgorithmA192CBC_HS384: nil,
	EncryptionAlgorithmA256CBC_HS512: nil,
	EncryptionAlgorithmA128GCM:       nil,
	EncryptionAlgorithmA192GCM:       nil,
	EncryptionAlgorithmA256GCM:       nil,
}

func RegisterEncryptionAlgorithm(alg EncryptionAlgorithm, f func() enc.Algorithm) {
	g, ok := encryptionAlgorithm[alg]
	if !ok {
		panic("jwa: RegisterEncryptionAlgorithm of unknown algorithm")
	}
	if g != nil {
		panic("jwa: RegisterEncryptionAlgorithm of already registered algorithm")
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

// CEKSize returns the byte size of CEK(Content Encryption Key) for the algorithm.
func (enc EncryptionAlgorithm) CEKSize() int {
	switch enc {
	case EncryptionAlgorithmA128CBC_HS256:
		return 32
	case EncryptionAlgorithmA192CBC_HS384:
		return 48
	case EncryptionAlgorithmA256CBC_HS512:
		return 64
	case EncryptionAlgorithmA128GCM:
		return 16
	case EncryptionAlgorithmA192GCM:
		return 24
	case EncryptionAlgorithmA256GCM:
		return 32
	}
	return 0
}

// IVSice returns the byte size of IV(Initialization Vector) for the algorithm.
func (enc EncryptionAlgorithm) IVSize() int {
	switch enc {
	case EncryptionAlgorithmA128CBC_HS256, EncryptionAlgorithmA192CBC_HS384, EncryptionAlgorithmA256CBC_HS512:
		return 16
	case EncryptionAlgorithmA128GCM, EncryptionAlgorithmA192GCM, EncryptionAlgorithmA256GCM:
		return 12
	}
	return 0
}

// KeyType is a key type defined in the IANA "JSON Web Key Types".
type KeyType string

const (
	// EC is Elliptic Curve.
	//
	// Deprecated: use [KeyTypeEC] instead of EC.
	//go:fix inline
	EC = KeyTypeEC

	// RSA is RSA.
	//
	// Deprecated: use [KeyTypeRSA] instead of RSA.
	//go:fix inline
	RSA = KeyTypeRSA

	// OKP is Octet string key pairs
	// defined in RFC 8037 Section 2. Key Type "OKP".
	//
	// Deprecated: use [KeyTypeOKP] instead of OKP.
	//go:fix inline
	OKP = KeyTypeOKP

	// Oct is Octet sequence (used to represent symmetric keys).
	//
	// Deprecated: use [KeyTypeOct] instead of Oct.
	//go:fix inline
	Oct = KeyTypeOct
)

const (
	KeyTypeUnknown KeyType = ""

	// KeyTypeEC is Elliptic Curve.
	KeyTypeEC KeyType = "EC"

	// KeyTypeRSA is RSA.
	KeyTypeRSA KeyType = "RSA"

	// KeyTypeOKP is Octet string key pairs
	// defined in RFC 8037 Section 2. Key Type "OKP".
	KeyTypeOKP KeyType = "OKP"

	// KeyTypeOct is Octet sequence (used to represent symmetric keys).
	KeyTypeOct KeyType = "oct"

	// KeyTypeAKP is Algorithm Key Pair defined in [I-D.ietf-cose-dilithium].
	//
	// [I-D.ietf-cose-dilithium]: https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/11/
	KeyTypeAKP KeyType = "AKP"
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
	//
	// Deprecated: use [EllipticCurveP256] instead of P256.
	//go:fix inline
	P256 = EllipticCurveP256

	// P384 is a Curve which implements NIST P-384.
	//
	// Deprecated: use [EllipticCurveP384] instead of P384.
	//go:fix inline
	P384 = EllipticCurveP384

	// P521 is a Curve which implements NIST P-521.
	//
	// Deprecated: use [EllipticCurveP521] instead of P521.
	//go:fix inline
	P521 = EllipticCurveP521

	// Ed25519 is Ed25519 signature algorithm key pairs.
	//
	// Deprecated: use [EllipticCurveEd25519] instead of Ed25519.
	//go:fix inline
	Ed25519 = EllipticCurveEd25519

	// Ed448 is Ed448 signature algorithm key pairs.
	//
	// Deprecated: use [EllipticCurveEd448] instead of Ed448.
	//go:fix inline
	Ed448 = EllipticCurveEd448

	// X25519 is X25519 function key pairs.
	//
	// Deprecated: use [EllipticCurveX25519] instead of X25519.
	//go:fix inline
	X25519 = EllipticCurveX25519

	// X448 is X448 function key pairs.
	//
	// Deprecated: use [EllipticCurveX448] instead of X448.
	//go:fix inline
	X448 = EllipticCurveX448

	// secp256k1 is SECG secp256k1 curve.
	//
	// Deprecated: use [EllipticCurveSecp256k1] instead of Secp256k1.
	//go:fix inline
	Secp256k1 = EllipticCurveSecp256k1
)

const (
	// EllipticCurveP256 is a Curve which implements NIST P-256.
	EllipticCurveP256 EllipticCurve = "P-256"

	// EllipticCurveP384 is a Curve which implements NIST P-384.
	EllipticCurveP384 EllipticCurve = "P-384"

	// EllipticCurveP521 is a Curve which implements NIST P-521.
	EllipticCurveP521 EllipticCurve = "P-521"

	// EllipticCurveEd25519 is Ed25519 signature algorithm key pairs.
	EllipticCurveEd25519 EllipticCurve = "Ed25519"

	// EllipticCurveEd448 is Ed448 signature algorithm key pairs.
	EllipticCurveEd448 EllipticCurve = "Ed448"

	// EllipticCurveX25519 is X25519 function key pairs.
	EllipticCurveX25519 EllipticCurve = "X25519"

	// EllipticCurveX448 is X448 function key pairs.
	EllipticCurveX448 EllipticCurve = "X448"

	// EllipticCurveSecp256k1 is SECG secp256k1 curve.
	EllipticCurveSecp256k1 EllipticCurve = "secp256k1"
)

func (crv EllipticCurve) String() string {
	return string(crv)
}

type CompressionAlgorithm string

const (
	// DEF is compression with the DEFLATE RFC 1951 algorithm.
	//
	// Deprecated: use [CompressionAlgorithmDEF] instead of DEF.
	//go:fix inline
	DEF = CompressionAlgorithmDEF
)

const (
	CompressionAlgorithmUnknown CompressionAlgorithm = ""

	// CompressionAlgorithmDEF is compression with the DEFLATE RFC 1951 algorithm.
	CompressionAlgorithmDEF CompressionAlgorithm = "DEF"
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
