package es

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/shogo82148/goat/secp256k1"
	"github.com/shogo82148/goat/sig"
)

var tests = []struct {
	alg   func() sig.Algorithm
	curve elliptic.Curve
	priv  string
	pub   string
	in    []byte
	sig   []byte
}{
	// test vectors from RFC 7515 Appendix A.3.
	{
		New256,
		elliptic.P256(),
		"8e9b109e719098bf980487df1f5d77e9cb29606ebed2263b5f57c213df84f4b2",
		"047fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad",
		[]byte{
			101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 85, 122, 73,
			49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105,
			74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67, 74, 108, 101, 72,
			65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84, 107, 122, 79, 68,
			65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65, 54, 76,
			121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118,
			98, 83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48,
			99, 110, 86, 108, 102, 81,
		},
		[]byte{
			// R
			14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88,
			7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129,
			154, 195, 22, 158, 166, 101,
			// S
			197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175,
			8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154,
			143, 63, 127, 138, 131, 163, 84, 213,
		},
	},

	// test vectors from RFC 7515 Appendix A.4.
	{
		New512,
		elliptic.P521(),
		"018e696fb034505881dd110b483eb87d32ce495fe36b3745edf2d8cae4f0f2539f4615a0e98eab52b3c0c5eac4ce075185a8e7bb47deac1d1de77bccf66135e63d82",
		"0401e929050f124fc6bc55c7d5393365df9def4ab0c22cb25798f934eb04e3c6bae3701a57a7910e9d81bf363159e8ebcb155d6349f4bdb6ccf8a94c5c59c7aac101a40034a6440e376750d2371fd1bdc2c8f3b71d2f4ee5ea3432c815cca31560fe5d9387ec774b55838630e5cbbf5a8cbe0a91dd0064c6999a1f6e6e67faddede4c8c8f6",
		[]byte{
			101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 85, 122, 85,
			120, 77, 105, 74, 57, 46, 85, 71, 70, 53, 98, 71, 57, 104, 90, 65,
		},
		[]byte{
			// R
			1, 220, 12, 129, 231, 171, 194, 209, 232, 135, 233,
			117, 247, 105, 122, 210, 26, 125, 192, 1, 217, 21, 82,
			91, 45, 240, 255, 83, 19, 34, 239, 71, 48, 157, 147,
			152, 105, 18, 53, 108, 163, 214, 68, 231, 62, 153, 150,
			106, 194, 164, 246, 72, 143, 138, 24, 50, 129, 223, 133,
			206, 209, 172, 63, 237, 119, 109,
			// S
			0, 111, 6, 105, 44, 5, 41, 208, 128, 61, 152, 40, 92,
			61, 152, 4, 150, 66, 60, 69, 247, 196, 170, 81, 193,
			199, 78, 59, 194, 169, 16, 124, 9, 143, 42, 142, 131,
			48, 206, 238, 34, 175, 83, 203, 220, 159, 3, 107, 155,
			22, 27, 73, 111, 68, 68, 21, 238, 144, 229, 232, 148,
			188, 222, 59, 242, 103,
		},
	},
}

type rawKey struct {
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
}

func (k *rawKey) PrivateKey() crypto.PrivateKey {
	return k.priv
}

func (k *rawKey) PublicKey() crypto.PublicKey {
	return k.pub
}

func TestVerify(t *testing.T) {
	for i, test := range tests {
		data, err := hex.DecodeString(test.pub)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(test.curve, data)
		if err != nil {
			t.Fatal(err)
		}

		alg := test.alg()
		key := alg.NewSigningKey(&rawKey{nil, pub})
		if err := key.Verify(test.in, test.sig); err != nil {
			t.Errorf("test %d: %v", i, err)
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	for i, test := range tests {
		data, err := hex.DecodeString(test.priv)
		if err != nil {
			t.Fatal(err)
		}
		priv, err := ecdsa.ParseRawPrivateKey(test.curve, data)
		if err != nil {
			t.Fatal(err)
		}

		alg := test.alg()
		key := alg.NewSigningKey(&rawKey{priv, &priv.PublicKey})
		sig, err := key.Sign(test.in)
		if err != nil {
			t.Errorf("test %d: %v", i, err)
		}
		if err := key.Verify(test.in, sig); err != nil {
			t.Errorf("test %d: %v", i, err)
		}
	}
}

type rawSecp256k1Key struct {
	priv *secp256k1.PrivateKey
	pub  *secp256k1.PublicKey
}

func (k *rawSecp256k1Key) PrivateKey() crypto.PrivateKey {
	return k.priv
}

func (k *rawSecp256k1Key) PublicKey() crypto.PublicKey {
	return k.pub
}

func TestSecp256k1(t *testing.T) {
	priv := secp256k1.GenerateKey()
	pub := priv.PublicKey()

	key := New256K().NewSigningKey(&rawSecp256k1Key{priv, pub})

	sig, err := key.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	if err := key.Verify([]byte("payload"), sig); err != nil {
		t.Fatal(err)
	}
}

func Test_InvalidCurve(t *testing.T) {
	invalidCases := []struct {
		alg func() sig.Algorithm
		crv elliptic.Curve
	}{
		{New256, elliptic.P384()},
		{New256, elliptic.P521()},
		{New384, elliptic.P256()},
		{New384, elliptic.P521()},
		{New512, elliptic.P256()},
		{New512, elliptic.P384()},
	}
	for i, test := range invalidCases {
		priv, err := ecdsa.GenerateKey(test.crv, rand.Reader)
		if err != nil {
			t.Errorf("test %d: %v", i, err)
		}
		alg := test.alg()

		key1 := alg.NewSigningKey(&rawKey{priv, nil})
		_, err = key1.Sign([]byte("payload"))
		if err == nil {
			t.Errorf("test %d: want error, but not", i)
		}

		key2 := alg.NewSigningKey(&rawKey{nil, &priv.PublicKey})
		err = key2.Verify([]byte("payload"), []byte{})
		if err == nil {
			t.Errorf("test %d: want error, but not", i)
		}
	}
}
