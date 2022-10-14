package ecdhes

import (
	"crypto/subtle"
	"encoding/hex"
	"testing"

	"github.com/shogo82148/goat/jwa"
	_ "github.com/shogo82148/goat/jwa/agcm"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/x25519"
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
	key := alg.NewKeyWrapper(aliceKey)
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

func decodeHex(s string) []byte {
	ret, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return ret
}

func TestX25519(t *testing.T) {
	alicePrivate := x25519.PrivateKey(decodeHex(
		"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a" +
			"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
	))
	alicePublic := x25519.PublicKey(decodeHex(
		"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
	))
	bobPrivate := x25519.PrivateKey(decodeHex(
		"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb" +
			"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
	))
	bobPublic := x25519.PublicKey(decodeHex(
		"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
	))
	want := decodeHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	got1, err := deriveZ(alicePrivate, bobPublic)
	if err != nil {
		t.Fatal(err)
	}
	if subtle.ConstantTimeCompare(want, got1) == 0 {
		t.Errorf("invalid secret: want %x, got %x", want, got1)
	}

	got2, err := deriveZ(bobPrivate, alicePublic)
	if err != nil {
		t.Fatal(err)
	}
	if subtle.ConstantTimeCompare(want, got2) == 0 {
		t.Errorf("invalid secret: want %x, got %x", want, got2)
	}
}
