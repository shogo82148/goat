// Package ecdhes implements Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES).
package ecdhes

import (
	"crypto"
	"crypto/ecdsa"
	_ "crypto/sha256" // for crypto.SHA256
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwa/akw"
	"github.com/shogo82148/goat/jwa/dir"
	"github.com/shogo82148/goat/keymanage"
)

var alg = &Algorithm{
	f: func(key []byte) keymanage.KeyWrapper {
		return dir.New().NewKeyWrapper(&dir.Options{
			Key: key,
		})
	},
}

// New returns a new algorithm
// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF.
func New() keymanage.Algorithm {
	return alg
}

var a128kw = &Algorithm{
	size: 16,
	f: func(key []byte) keymanage.KeyWrapper {
		return akw.New128().NewKeyWrapper(&akw.Options{
			Key: key,
		})
	},
}

// NewA128KW returns a new algorithm ECDH-ES using Concat KDF and CEK wrapped with "A128KW".
func NewA128KW() keymanage.Algorithm {
	return a128kw
}

var a192kw = &Algorithm{
	size: 24,
	f: func(key []byte) keymanage.KeyWrapper {
		return akw.New192().NewKeyWrapper(&akw.Options{
			Key: key,
		})
	},
}

// NewA192KW returns a new algorithm ECDH-ES using Concat KDF and CEK wrapped with "A192KW".
func NewA192KW() keymanage.Algorithm {
	return a192kw
}

var a256kw = &Algorithm{
	size: 32,
	f: func(key []byte) keymanage.KeyWrapper {
		return akw.New256().NewKeyWrapper(&akw.Options{
			Key: key,
		})
	},
}

// NewA256KW returns a new algorithm ECDH-ES using Concat KDF and CEK wrapped with "A256KW".
func NewA256KW() keymanage.Algorithm {
	return a256kw
}

func init() {
	jwa.RegisterKeyManagementAlgorithm(jwa.ECDH_ES, New)
	jwa.RegisterKeyManagementAlgorithm(jwa.ECDH_ES_A128KW, NewA128KW)
	jwa.RegisterKeyManagementAlgorithm(jwa.ECDH_ES_A192KW, NewA192KW)
	jwa.RegisterKeyManagementAlgorithm(jwa.ECDH_ES_A256KW, NewA256KW)
}

var _ keymanage.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	size int
	f    func([]byte) keymanage.KeyWrapper
}

type Options struct {
	PrivateKey any

	// EncryptionAlgorithm is "enc" (Encryption Algorithm) Header Parameter.
	EncryptionAlgorithm jwa.EncryptionAlgorithm

	// EphemeralPublicKey is "epk" (Ephemeral Public Key) Header Parameter.
	EphemeralPublicKey any

	// AgreementPartyUInfo is "apu" (Agreement PartyUInfo) Header Parameter.
	AgreementPartyUInfo []byte

	// AgreementPartyVInfo is "apv" (Agreement PartyVInfo) Header Parameter.
	AgreementPartyVInfo []byte
}

// NewKeyWrapper implements [github.com/shogo82148/goat/keymanage.Algorithm].
// opts must be a pointer to [Options].
func (alg *Algorithm) NewKeyWrapper(opts any) keymanage.KeyWrapper {
	key, ok := opts.(*Options)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("ecdhes: invalid option type: %T", opts))
	}
	size := alg.size
	if size == 0 {
		size = key.EncryptionAlgorithm.New().CEKSize()
	}
	return &KeyWrapper{
		alg:  []byte(key.EncryptionAlgorithm.String()),
		size: size,
		f:    alg.f,
		opts: *key,
	}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
	alg  []byte
	size int
	f    func([]byte) keymanage.KeyWrapper
	opts Options
}

func (w *KeyWrapper) WrapKey(cek []byte) ([]byte, error) {
	return []byte{}, nil
}

func (w *KeyWrapper) UnwrapKey(data []byte) ([]byte, error) {
	key, err := deriveECDHES(
		w.alg,
		w.opts.AgreementPartyUInfo,
		w.opts.AgreementPartyVInfo,
		w.opts.PrivateKey,
		w.opts.EphemeralPublicKey,
		w.size,
	)
	if err != nil {
		return nil, err
	}
	return w.f(key).UnwrapKey(data)
}

func deriveECDHES(alg, apu, apv []byte, priv, pub any, keySize int) ([]byte, error) {
	z, err := deriveZ(priv, pub)
	if err != nil {
		return nil, err
	}

	var pubinfo [4]byte
	bits := keySize * 8
	pubinfo[0] = byte(bits >> 24)
	pubinfo[1] = byte(bits >> 16)
	pubinfo[2] = byte(bits >> 8)
	pubinfo[3] = byte(bits)

	r := newKDF(crypto.SHA256, z, alg, apu, apv, pubinfo[:], []byte{})
	key := make([]byte, keySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func deriveZ(priv, pub any) ([]byte, error) {
	switch priv := priv.(type) {
	case *ecdsa.PrivateKey:
		pubkey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("ecdhes: want *ecdsa.PrivateKey but got %T", pub)
		}
		crv := priv.Curve
		if pubkey.Curve != crv || !crv.IsOnCurve(pubkey.X, pubkey.Y) {
			return nil, errors.New("ecdhes: public key must be on the same curve as private key")
		}
		z, _ := crv.ScalarMult(pubkey.X, pubkey.Y, priv.D.Bytes())
		size := (crv.Params().BitSize + 7) / 8
		buf := make([]byte, size)
		return z.FillBytes(buf), nil
	default:
		return nil, fmt.Errorf("ecdhes: unknown private key type: %T", priv)
	}
}

type kdf struct {
	hash hash.Hash

	z []byte

	// AlgorithmID
	alg []byte

	// PartyUInfo, PartyVInfo
	apu, apv []byte

	// SuppPubInfo, SuppPrivInfo
	pub, priv []byte

	round uint32
	n     int
	buf   []byte
}

func newKDF(hash crypto.Hash, z, alg, apu, apv, pub, priv []byte) *kdf {
	h := hash.New()
	size := h.Size()
	if size < 4 {
		size = 4
	}
	return &kdf{
		z:    z,
		hash: h,
		alg:  alg,
		apu:  apu,
		apv:  apv,
		pub:  pub,
		priv: priv,
		buf:  make([]byte, size),
	}
}

func (r *kdf) Read(data []byte) (n int, err error) {
	if r.n == 0 {
		r.round++
		r.hash.Reset()

		r.putUint32(r.round)
		r.hash.Write(r.z)
		r.putUint32(uint32(len(r.alg)))
		r.hash.Write(r.alg)
		r.putUint32(uint32(len(r.apu)))
		r.hash.Write(r.apu)
		r.putUint32(uint32(len(r.apv)))
		r.hash.Write(r.apv)
		r.hash.Write(r.pub)
		r.hash.Write(r.priv)

		r.buf = r.hash.Sum(r.buf[:0])
		r.n = len(r.buf)
	}
	n = copy(data, r.buf[len(r.buf)-r.n:])
	r.n -= n
	return
}

func (r *kdf) putUint32(v uint32) {
	buf := r.buf[:4]
	buf[0] = byte(v >> 24)
	buf[1] = byte(v >> 16)
	buf[2] = byte(v >> 8)
	buf[3] = byte(v)
	r.hash.Write(buf)
}
