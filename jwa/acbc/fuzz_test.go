package acbc

import (
	"crypto/subtle"
	"testing"
)

func FuzzDecrypt(f *testing.F) {
	// RFC 7516 Appendix A.3. Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
	cek := []byte{
		4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
		206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
		44, 207,
	}
	iv := []byte{
		3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
		101,
	}
	aad := []byte{
		101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
		120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105,
		74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85,
		50, 73, 110, 48,
	}
	ciphertext := []byte{
		40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
		75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
		112, 56, 102,
	}
	authTag := []byte{
		246, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100,
		191,
	}
	f.Add(cek, iv, aad, ciphertext, authTag)

	f.Fuzz(func(t *testing.T, cek, iv, aad, ciphertext, authTag []byte) {
		enc := New128HS256()
		enc.Decrypt(cek, iv, aad, ciphertext, authTag)
	})
}

func FuzzEncrypt(f *testing.F) {
	cek := []byte{
		4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
		206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
		44, 207,
	}
	iv := []byte{
		3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
		101,
	}
	aad := []byte{
		101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
		120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105,
		74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85,
		50, 73, 110, 48,
	}
	plaintext := []byte{
		76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
		112, 114, 111, 115, 112, 101, 114, 46,
	}
	f.Add(cek, iv, aad, plaintext)

	f.Fuzz(func(t *testing.T, cek, iv, aad, plaintext []byte) {
		enc := New128HS256()
		ciphertext, authTag, err := enc.Encrypt(cek, iv, aad, plaintext)
		if err != nil {
			return
		}
		got, err := enc.Decrypt(cek, iv, aad, ciphertext, authTag)
		if err != nil {
			t.Error(err)
		}
		if subtle.ConstantTimeCompare(plaintext, got) == 0 {
			t.Error("failed to decrypt")
		}
	})
}
