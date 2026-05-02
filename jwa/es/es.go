// package es provides the ECDSA using SHA-2 signature algorithm.
package es

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha512" // for crypto.SHA512
	"encoding/asn1"
	"math/big"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk/jwktypes"
	"github.com/shogo82148/goat/secp256k1"
	"github.com/shogo82148/goat/sig"
)

var es256 = &algorithm{
	alg:  jwa.SignatureAlgorithmES256,
	hash: crypto.SHA256,
	crv:  elliptic.P256(),
}

// New256 returns ECDSA using P-256 and SHA-256.
func New256() sig.Algorithm {
	return es256
}

var es256k = &algorithm{
	alg:  jwa.SignatureAlgorithmES256K,
	hash: crypto.SHA256,
	crv:  secp256k1.Curve(), //nolint:staticcheck // for backward compatibility
}

// New256K returns ECDSA using secp256k1 and SHA-256.
func New256K() sig.Algorithm {
	return &algorithmES256K{}
}

var es384 = &algorithm{
	alg:  jwa.SignatureAlgorithmES384,
	hash: crypto.SHA384,
	crv:  elliptic.P384(),
}

// New384 returns ECDSA using P-384 and SHA-384.
func New384() sig.Algorithm {
	return es384
}

var es512 = &algorithm{
	alg:  jwa.SignatureAlgorithmES512,
	hash: crypto.SHA512,
	crv:  elliptic.P521(),
}

// New512 returns ECDSA using P-521 and SHA-512.
func New512() sig.Algorithm {
	return es512
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.SignatureAlgorithmES256, New256)
	jwa.RegisterSignatureAlgorithm(jwa.SignatureAlgorithmES384, New384)
	jwa.RegisterSignatureAlgorithm(jwa.SignatureAlgorithmES512, New512)
	jwa.RegisterSignatureAlgorithm(jwa.SignatureAlgorithmES256K, New256K)
}

var _ sig.Algorithm = (*algorithm)(nil)

type algorithm struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
	crv  elliptic.Curve
}

var _ sig.SigningKey = (*signingKey)(nil)

type signingKey struct {
	hash      crypto.Hash
	priv      *ecdsa.PrivateKey
	pub       *ecdsa.PublicKey
	canSign   bool
	canVerify bool
}

// NewSigningKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *algorithm) NewSigningKey(key sig.Key) sig.SigningKey {
	k := &signingKey{
		hash:      alg.hash,
		canSign:   jwktypes.CanUseFor(key, jwktypes.KeyOpSign),
		canVerify: jwktypes.CanUseFor(key, jwktypes.KeyOpVerify),
	}

	priv := key.PrivateKey()
	pub := key.PublicKey()
	if key, ok := priv.(*ecdsa.PrivateKey); ok {
		k.priv = key
	} else if priv != nil {
		return sig.NewInvalidKey(alg.alg.String(), priv, pub)
	}
	if key, ok := pub.(*ecdsa.PublicKey); ok {
		k.pub = key
	} else if priv != nil {
		return sig.NewInvalidKey(alg.alg.String(), priv, pub)
	}

	if k.priv != nil {
		if k.priv.Curve != alg.crv {
			return sig.NewInvalidKey(alg.alg.String(), priv, pub)
		}
	}
	if k.pub != nil {
		if k.pub.Curve != alg.crv {
			return sig.NewInvalidKey(alg.alg.String(), priv, pub)
		}
	}
	return k
}

// Sign implements [github.com/shogo82148/goat/sig.Key].
func (key *signingKey) Sign(payload []byte) (signature []byte, err error) {
	if !key.hash.Available() {
		return nil, sig.ErrHashUnavailable
	}
	if key.priv == nil || !key.canSign {
		return nil, sig.ErrSignUnavailable
	}

	hash := key.hash.New()
	if _, err := hash.Write(payload); err != nil {
		return nil, err
	}
	sum := hash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, key.priv, sum)
	if err != nil {
		return nil, err
	}
	bits := key.priv.Curve.Params().BitSize
	size := (bits + 7) / 8

	ret := make([]byte, 2*size)
	r.FillBytes(ret[:size])
	s.FillBytes(ret[size:])
	return ret, nil
}

// Verify implements [github.com/shogo82148/goat/sig.Key].
func (key *signingKey) Verify(payload, signature []byte) error {
	if !key.hash.Available() {
		return sig.ErrHashUnavailable
	}
	if key.pub == nil || !key.canVerify {
		return sig.ErrSignUnavailable
	}

	bits := key.pub.Curve.Params().BitSize
	size := (bits + 7) / 8
	if len(signature) != 2*size {
		return sig.ErrSignatureMismatch
	}

	hash := key.hash.New()
	if _, err := hash.Write(payload); err != nil {
		return err
	}
	sum := hash.Sum(nil)

	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	if !ecdsa.Verify(key.pub, sum, r, s) {
		return sig.ErrSignatureMismatch
	}
	return nil
}

var _ sig.Algorithm = (*algorithmES256K)(nil)

type algorithmES256K struct{}

// NewSigningKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (*algorithmES256K) NewSigningKey(sigKey sig.Key) sig.SigningKey {
	k := &signingKeyES256K{
		canSign:   jwktypes.CanUseFor(sigKey, jwktypes.KeyOpSign),
		canVerify: jwktypes.CanUseFor(sigKey, jwktypes.KeyOpVerify),
	}

	priv := sigKey.PrivateKey()
	pub := sigKey.PublicKey()

	if key, ok := priv.(*secp256k1.PrivateKey); ok {
		k.priv = key
	} else if _, ok := priv.(*ecdsa.PrivateKey); ok {
		return es256k.NewSigningKey(sigKey)
	} else if priv != nil {
		return sig.NewInvalidKey(jwa.SignatureAlgorithmES256K.String(), priv, pub)
	}
	if key, ok := pub.(*secp256k1.PublicKey); ok {
		k.pub = key
	} else if _, ok := pub.(*ecdsa.PublicKey); ok {
		return es256k.NewSigningKey(sigKey)
	} else if pub != nil {
		return sig.NewInvalidKey(jwa.SignatureAlgorithmES256K.String(), priv, pub)
	}
	return k
}

type signingKeyES256K struct {
	priv      *secp256k1.PrivateKey
	pub       *secp256k1.PublicKey
	canSign   bool
	canVerify bool
}

// Sign implements [github.com/shogo82148/goat/sig.Key].
func (key *signingKeyES256K) Sign(payload []byte) (signature []byte, err error) {
	if key.priv == nil || !key.canSign {
		return nil, sig.ErrSignUnavailable
	}

	digest := sha256.Sum256(payload)
	sig, err := secp256k1.SignASN1(key.priv, digest[:])
	if err != nil {
		return nil, err
	}

	var s struct {
		R *big.Int
		S *big.Int
	}
	if _, err := asn1.Unmarshal(sig, &s); err != nil {
		return nil, err
	}
	signature = make([]byte, 64)
	s.R.FillBytes(signature[:32])
	s.S.FillBytes(signature[32:])
	return signature, nil
}

// Verify implements [github.com/shogo82148/goat/sig.Key].
func (key *signingKeyES256K) Verify(payload, signature []byte) error {
	if key.pub == nil || !key.canVerify {
		return sig.ErrSignUnavailable
	}

	if len(signature) != 64 {
		return sig.ErrSignatureMismatch
	}

	digest := sha256.Sum256(payload)
	s := struct {
		R *big.Int
		S *big.Int
	}{
		R: new(big.Int).SetBytes(signature[:32]),
		S: new(big.Int).SetBytes(signature[32:]),
	}
	asn1sig, err := asn1.Marshal(s)
	if err != nil {
		return err
	}

	if !secp256k1.VerifyASN1(key.pub, digest[:], asn1sig) {
		return sig.ErrSignatureMismatch
	}
	return nil
}
