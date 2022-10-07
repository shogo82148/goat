package jwktypes

// KeyUse is type of "use" JWK parameter
// defined in RFC 7517 Section 4.2.
type KeyUse string

const (
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

type KeyOp string

const (
	KeyOpSign       KeyOp = "sign"
	KeyOpVerify     KeyOp = "verify"
	KeyOpEncrypt    KeyOp = "encrypt"
	KeyOpDecrypt    KeyOp = "decrypt"
	KeyOpWrapKey    KeyOp = "wrapKey"
	KeyOpUnwrapKey  KeyOp = "unwrapKey"
	KeyOpDeriveKey  KeyOp = "deriveKey"
	KeyOpDeriveBits KeyOp = "deriveBits"
)
