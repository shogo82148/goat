package ecdhes

import (
	"crypto/subtle"
	"testing"

	"github.com/shogo82148/goat/jwa"
	_ "github.com/shogo82148/goat/jwa/agcm"
	"github.com/shogo82148/goat/jwk"
)

type options struct {
	enc jwa.EncryptionAlgorithm
	epk *jwk.Key
	apu []byte
	apv []byte
}

func (opts *options) Encryption() jwa.EncryptionAlgorithm {
	return opts.enc
}

func (opts *options) EphemeralPublicKey() *jwk.Key {
	return opts.epk
}

func (opts *options) AgreementPartyUInfo() []byte {
	return opts.apu
}

func (opts *options) AgreementPartyVInfo() []byte {
	return opts.apv
}

func TestUnwrap(t *testing.T) {
	// RFC 7518 Appendix C. Example ECDH-ES Key Agreement Computation
	alice := `{"kty":"EC",` +
		`"crv":"P-256",` +
		`"x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",` +
		`"y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",` +
		`"d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"` +
		`}`
	aliceKey, err := jwk.ParseKey([]byte(alice))
	if err != nil {
		t.Fatal(err)
	}

	bob := `{"kty":"EC",` +
		`"crv":"P-256",` +
		`"x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",` +
		`"y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",` +
		`"d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"` +
		`}`
	bobKey, err := jwk.ParseKey([]byte(bob))
	if err != nil {
		t.Fatal(err)
	}

	alg := New()
	key := alg.NewKeyWrapper(aliceKey.KeyPair())
	opts := &options{
		enc: jwa.A128GCM,
		epk: bobKey,
		apu: []byte("Alice"),
		apv: []byte("Bob"),
	}

	got, err := key.UnwrapKey([]byte{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26,
	}
	if subtle.ConstantTimeCompare(want, got) == 0 {
		t.Errorf("want %#v, got %#v", want, got)
	}
}
