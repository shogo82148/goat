package es

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/shogo82148/goat/sig"
)

func newBigInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("failed to parse " + s)
	}
	return n
}

var tests = []struct {
	alg  func() sig.Algorithm
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
	in   []byte
	sig  []byte
}{
	{
		New256,
		&ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     newBigInt("57807358241436249728379122087876380298924820027722995515715270765240753673285"),
				Y:     newBigInt("90436541859143682268950424386863654389577770182238183823381687388274600502701"),
			},
			D: newBigInt("64502400493437371358766275827725703314178640739253280897215993954599262549170"),
		},
		&ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     newBigInt("57807358241436249728379122087876380298924820027722995515715270765240753673285"),
			Y:     newBigInt("90436541859143682268950424386863654389577770182238183823381687388274600502701"),
		},
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
	{
		New512,
		&ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P521(),
				X:     newBigInt("6558566456959953544109522959384633002634366184193672267866407124696200040032063394775499664830638630438428532794662648623689740875293641365317574204038644132"),
				Y:     newBigInt("705914061082973601048865942513844186912223650952616397119610620188911564288314145208762412315826061109317770515164005156360031161563418113875601542699600118"),
			},
			D: newBigInt("5341829702302574813496892344628933729576493483297373613204193688404465422472930583369539336694834830511678939023627363969939187661870508700291259319376559490"),
		},
		&ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     newBigInt("6558566456959953544109522959384633002634366184193672267866407124696200040032063394775499664830638630438428532794662648623689740875293641365317574204038644132"),
			Y:     newBigInt("705914061082973601048865942513844186912223650952616397119610620188911564288314145208762412315826061109317770515164005156360031161563418113875601542699600118"),
		},
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
		alg := test.alg()
		key := alg.NewSigningKey(&rawKey{nil, test.pub})
		if err := key.Verify(test.in, test.sig); err != nil {
			t.Errorf("test %d: %v", i, err)
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	for i, test := range tests {
		alg := test.alg()
		key := alg.NewSigningKey(&rawKey{test.priv, test.pub})
		sig, err := key.Sign(test.in)
		if err != nil {
			t.Errorf("test %d: %v", i, err)
		}
		if err := key.Verify(test.in, sig); err != nil {
			t.Errorf("test %d: %v", i, err)
		}
	}
}

func TestSign_NilPublicKey(t *testing.T) {
	for i, test := range tests {
		alg := test.alg()
		key := alg.NewSigningKey(&rawKey{test.priv, nil})
		sig, err := key.Sign(test.in)
		if err != nil {
			t.Errorf("test %d: %v", i, err)
		}
		if err := key.Verify(test.in, sig); err != nil {
			t.Errorf("test %d: %v", i, err)
		}
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
