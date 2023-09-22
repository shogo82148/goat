package jwk

import (
	"os"
	"testing"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk/jwktypes"
)

func TestRFC7520(t *testing.T) {
	t.Run("3.1. EC Public Key", func(t *testing.T) {
		data, err := os.ReadFile("testdata/rfc7520/3_1.ec_public_key.json")
		if err != nil {
			t.Fatal(err)
		}
		key, err := ParseKey(data)
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != jwa.EC {
			t.Errorf("unexpected key type: want %s, got %s", jwa.EC, key.KeyType())
		}
	})

	t.Run("3.2. EC Private Key", func(t *testing.T) {
		data, err := os.ReadFile("testdata/rfc7520/3_2.ec_private_key.json")
		if err != nil {
			t.Fatal(err)
		}
		key, err := ParseKey(data)
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != jwa.EC {
			t.Errorf("unexpected key type: want %s, got %s", jwa.EC, key.KeyType())
		}
		if key.PublicKeyUse() != jwktypes.KeyUseSig {
			t.Errorf("unexpected key use: want %s, got %s", jwktypes.KeyUseSig, key.PublicKeyUse())
		}
	})

	t.Run("3.3. RSA Public Key", func(t *testing.T) {
		data, err := os.ReadFile("testdata/rfc7520/3_3.rsa_public_key.json")
		if err != nil {
			t.Fatal(err)
		}
		key, err := ParseKey(data)
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != jwa.RSA {
			t.Errorf("unexpected key type: want %s, got %s", jwa.EC, key.KeyType())
		}
		if key.PublicKeyUse() != jwktypes.KeyUseSig {
			t.Errorf("unexpected key use: want %s, got %s", jwktypes.KeyUseSig, key.PublicKeyUse())
		}
	})

	t.Run("3.4. RSA Private Key", func(t *testing.T) {
		data, err := os.ReadFile("testdata/rfc7520/3_4.rsa_private_key.json")
		if err != nil {
			t.Fatal(err)
		}
		key, err := ParseKey(data)
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != jwa.RSA {
			t.Errorf("unexpected key type: want %s, got %s", jwa.EC, key.KeyType())
		}
		if key.PublicKeyUse() != jwktypes.KeyUseSig {
			t.Errorf("unexpected key use: want %s, got %s", jwktypes.KeyUseSig, key.PublicKeyUse())
		}
	})

	t.Run("3.5. Symmetric Key (MAC Computation)", func(t *testing.T) {
		data, err := os.ReadFile("testdata/rfc7520/3_5.symmetric_key_mac_computation.json")
		if err != nil {
			t.Fatal(err)
		}
		key, err := ParseKey(data)
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != jwa.Oct {
			t.Errorf("unexpected key type: want %s, got %s", jwa.EC, key.KeyType())
		}
		if key.PublicKeyUse() != jwktypes.KeyUseSig {
			t.Errorf("unexpected key use: want %s, got %s", jwktypes.KeyUseSig, key.PublicKeyUse())
		}
	})

	t.Run("3.6. Symmetric Key (Encryption) ", func(t *testing.T) {
		data, err := os.ReadFile("testdata/rfc7520/3_6.symmetric_key_encryption.json")
		if err != nil {
			t.Fatal(err)
		}
		key, err := ParseKey(data)
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != jwa.Oct {
			t.Errorf("unexpected key type: want %s, got %s", jwa.EC, key.KeyType())
		}
		if key.PublicKeyUse() != jwktypes.KeyUseEnc {
			t.Errorf("unexpected key use: want %s, got %s", jwktypes.KeyUseEnc, key.PublicKeyUse())
		}
	})
}
