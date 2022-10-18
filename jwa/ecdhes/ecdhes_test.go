package ecdhes

import (
	"crypto/subtle"
	"encoding/hex"
	"testing"

	"github.com/shogo82148/goat/jwa"
	_ "github.com/shogo82148/goat/jwa/agcm"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/x25519"
	"github.com/shogo82148/goat/x448"
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
	// RFC 7748 Section 6.1 Curve25519
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

func TestX448(t *testing.T) {
	// RFC 7748 Section 6.2 Curve448
	alicePrivate := x448.PrivateKey(decodeHex(
		"9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d" +
			"d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b" +
			"9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c" +
			"22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
	))
	alicePublic := x448.PublicKey(decodeHex(
		"9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c" +
			"22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
	))
	bobPrivate := x448.PrivateKey(decodeHex(
		"1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d" +
			"6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d" +
			"3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430" +
			"27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
	))
	bobPublic := x448.PublicKey(decodeHex(
		"3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430" +
			"27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
	))
	want := decodeHex(
		"07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b" +
			"b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
	)

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
