// Package ecdhes provides the Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES)
// key agreement algorithm defined in RFC 6278.
package ecdhes

import (
	"crypto"
	"crypto/rand"
	_ "crypto/sha256" // for crypto.SHA256
	"fmt"
	"hash"
	"io"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwa/akw"
	"github.com/shogo82148/goat/jwa/dir"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/jwk/jwktypes"
	"github.com/shogo82148/goat/keymanage"
)

var alg = &Algorithm{
	alg: dir.New(),
}

// New returns a new algorithm
// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF.
func New() keymanage.Algorithm {
	return alg
}

var a128kw = &Algorithm{
	size: 16,
	alg:  akw.New128(),
}

// NewA128KW returns a new algorithm ECDH-ES using Concat KDF and CEK wrapped with "A128KW".
func NewA128KW() keymanage.Algorithm {
	return a128kw
}

var a192kw = &Algorithm{
	size: 24,
	alg:  akw.New192(),
}

// NewA192KW returns a new algorithm ECDH-ES using Concat KDF and CEK wrapped with "A192KW".
func NewA192KW() keymanage.Algorithm {
	return a192kw
}

var a256kw = &Algorithm{
	size: 32,
	alg:  akw.New256(),
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
	alg  keymanage.Algorithm
}

type encryptionGetter interface {
	Encryption() jwa.EncryptionAlgorithm
}

type ephemeralPublicKeyGetter interface {
	EphemeralPublicKey() *jwk.Key
}

type agreementPartyUInfoGetter interface {
	AgreementPartyUInfo() []byte
}

type agreementPartyVInfoGetter interface {
	AgreementPartyVInfo() []byte
}

// NewKeyWrapper implements [github.com/shogo82148/goat/keymanage.Algorithm].
func (alg *Algorithm) NewKeyWrapper(key keymanage.Key) keymanage.KeyWrapper {
	return &KeyWrapper{
		priv:      key.PrivateKey(),
		alg:       alg,
		canDerive: jwktypes.CanUseFor(key, jwktypes.KeyOpDeriveKey),
	}
}

type bytesKey []byte

func (k bytesKey) PrivateKey() crypto.PrivateKey {
	return []byte(k)
}

func (k bytesKey) PublicKey() crypto.PublicKey {
	return nil
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
	priv      any
	alg       *Algorithm
	canDerive bool
}

func (w *KeyWrapper) WrapKey(cek []byte, opts any) ([]byte, error) {
	return []byte{}, nil
}

func (w *KeyWrapper) UnwrapKey(data []byte, opts any) ([]byte, error) {
	if !w.canDerive {
		return nil, fmt.Errorf("ecdhes: key derive operation is not allowed")
	}

	enc, epk, apu, apv, err := getParams(opts)
	if err != nil {
		return nil, err
	}
	cekSize := enc.CEKSize()
	size := w.alg.size
	if size == 0 {
		size = cekSize
	}
	key, err := deriveECDHES(
		[]byte(enc),
		apu,
		apv,
		w.priv,
		epk.PublicKey(),
		size,
	)
	if err != nil {
		return nil, err
	}
	return w.alg.alg.NewKeyWrapper(bytesKey(key)).UnwrapKey(data, opts)
}

func (w *KeyWrapper) DeriveKey(opts any) (cek, encryptedCEK []byte, err error) {
	if !w.canDerive {
		return nil, nil, fmt.Errorf("ecdhes: key derive operation is not allowed")
	}

	enc, epk, apu, apv, err := getParams(opts)
	if err != nil {
		return nil, nil, err
	}
	cekSize := enc.CEKSize()
	size := w.alg.size
	if size == 0 {
		size = cekSize
	}
	key, err := deriveECDHES(
		[]byte(enc),
		apu,
		apv,
		w.priv,
		epk.PublicKey(),
		size,
	)
	if err != nil {
		return nil, nil, err
	}

	cek = make([]byte, cekSize)
	if _, err := rand.Read(cek); err != nil {
		return nil, nil, err
	}
	encryptedCEK, err = w.alg.alg.NewKeyWrapper(bytesKey(key)).WrapKey(cek, opts)
	if err != nil {
		return nil, nil, err
	}
	return cek, encryptedCEK, nil
}

func getParams(opts any) (enc jwa.EncryptionAlgorithm, epk *jwk.Key, apu, apv []byte, err error) {
	enc0, ok := opts.(encryptionGetter)
	if !ok {
		err = fmt.Errorf("ecdhes: method Encryption not found")
		return
	}
	epk0, ok := opts.(ephemeralPublicKeyGetter)
	if !ok {
		err = fmt.Errorf("ecdhes: method EphemeralPublicKey not found")
		return
	}
	apu0, ok := opts.(agreementPartyUInfoGetter)
	if !ok {
		err = fmt.Errorf("ecdhes: method AgreementPartyUInfo not found")
	}
	apv0, ok := opts.(agreementPartyVInfoGetter)
	if !ok {
		err = fmt.Errorf("ecdhes: method AgreementPartyVInfo not found")
	}

	enc = enc0.Encryption()
	epk = epk0.EphemeralPublicKey()
	apu = apu0.AgreementPartyUInfo()
	apv = apv0.AgreementPartyVInfo()
	return
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
