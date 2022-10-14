package jwk

import (
	"testing"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/x25519"
)

func TestParse_X25519(t *testing.T) {
	t.Run("RFC 8037 Appendix A.6. ECDH-ES with X25519", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"X25519","kid":"Bob",` +
			`"x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.kty != jwa.OKP {
			t.Errorf("unexpected key type: want %s, got %s", "OKP", key.kty)
		}

		publicKey := x25519.PublicKey{
			0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
			0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
		}
		if !publicKey.Equal(key.PublicKey()) {
			t.Errorf("unexpected public key: want %x, got %x", publicKey, key.PublicKey())
		}
	})
}
