// Package jwktypes contains types used by the package jwk.
package jwktypes

// KeyUse is type of "use" JWK parameter
// defined in RFC 7517 Section 4.2.
type KeyUse string

const (
	KeyUseUnknown KeyUse = ""

	// KeyUseSig is the value used in the headers to indicate that
	// this key should be used for signatures.
	KeyUseSig KeyUse = "sig"

	// KeyUseEnc is the value used in the headers to indicate that
	// this key should be used for encrypting.
	KeyUseEnc KeyUse = "enc"
)

func (use KeyUse) String() string {
	return string(use)
}

// KeyOp is type of "key_ops" JWK parameter
// defined in RFC 7517 Section 4.3.
type KeyOp string

const (
	// KeyOpSign is used for computing digital signature or MAC.
	KeyOpSign KeyOp = "sign"

	// KeyOpVerify is used for verifying digital signature or MAC
	KeyOpVerify KeyOp = "verify"

	// KeyOpVerify is used for encrypting content
	KeyOpEncrypt KeyOp = "encrypt"

	// KeyOpDecrypt is used for decrypt content and validate decryption, if applicable
	KeyOpDecrypt KeyOp = "decrypt"

	// KeyOpWrapKey is used for encrypt key
	KeyOpWrapKey KeyOp = "wrapKey"

	// KeyOpUnwrapKey is used for decrypt key and validate decryption, if applicable
	KeyOpUnwrapKey KeyOp = "unwrapKey"

	// KeyOpDeriveKey is used for deriving key
	KeyOpDeriveKey KeyOp = "deriveKey"

	// KeyOpDeriveBits is used for deriving bits not to be used as a key
	KeyOpDeriveBits KeyOp = "deriveBits"
)

type keyUse interface {
	PublicKeyUse() KeyUse
}

type keyOps interface {
	KeyOperations() []KeyOp
}

func CanUseFor(key any, op KeyOp) bool {
	return checkKeyOps(key, op) && checkKeyUse(key, op)
}

func checkKeyOps(key any, op KeyOp) bool {
	getter, ok := key.(keyOps)
	if !ok {
		return true
	}

	ops := getter.KeyOperations()
	if ops == nil {
		return true
	}

	for _, v := range ops {
		if v == op {
			return true
		}
	}

	return false
}

func checkKeyUse(key any, op KeyOp) bool {
	getter, ok := key.(keyUse)
	if !ok {
		return true
	}

	use := getter.PublicKeyUse()
	switch use {
	case KeyUseUnknown:
		return true
	case KeyUseSig:
		return op == KeyOpVerify
	case KeyUseEnc:
		return op == KeyOpEncrypt || op == KeyOpWrapKey || op == KeyOpDeriveKey
	default:
		return false
	}
}
