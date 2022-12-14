package agcm

import (
	"bytes"
	"math"
	"testing"

	"github.com/shogo82148/goat/jwa"
)

func TestDecrypt(t *testing.T) {
	// RFC 7516 Appendix A.1 Example JWE using RSAES-OAEP and AES GCM
	enc := New256()
	cek := []byte{
		177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
		212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
		234, 64, 252,
	}
	iv := []byte{
		227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219,
	}
	aad := []byte{
		101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
		116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
		54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81,
	}
	ciphertext := []byte{
		229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
		233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
		104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
		123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
		160, 109, 64, 63, 192,
	}
	authTag := []byte{
		92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
		210, 145,
	}
	got, err := enc.Decrypt(cek, iv, aad, ciphertext, authTag)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte{
		84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
		111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
		101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
		101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
		110, 97, 116, 105, 111, 110, 46,
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("want %#v, got %#v", plaintext, got)
	}
}

func TestEncrypt(t *testing.T) {
	// RFC 7516 Appendix A.1 Example JWE using RSAES-OAEP and AES GCM
	enc := New256()
	plaintext := []byte{
		84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
		111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
		101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
		101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
		110, 97, 116, 105, 111, 110, 46,
	}
	cek := []byte{
		177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
		212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
		234, 64, 252,
	}
	iv := []byte{
		227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219,
	}
	aad := []byte{
		101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
		116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
		54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81,
	}
	ciphertext, authTag, err := enc.Encrypt(cek, iv, aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	wantCiphertext := []byte{
		229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
		233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
		104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
		123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
		160, 109, 64, 63, 192,
	}
	if !bytes.Equal(ciphertext, wantCiphertext) {
		t.Errorf("want %#v, got %#v", wantCiphertext, ciphertext)
	}

	wantAuthTag := []byte{
		92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
		210, 145,
	}
	if !bytes.Equal(authTag, wantAuthTag) {
		t.Errorf("want %#v, got %#v", wantAuthTag, authTag)
	}
}

func TestCEKSize_and_IVSize(t *testing.T) {
	tests := []jwa.EncryptionAlgorithm{
		jwa.A128GCM,
		jwa.A192GCM,
		jwa.A256GCM,
	}
	for _, enc := range tests {
		enc1 := enc.New()
		cek, err := enc1.GenerateCEK()
		if err != nil {
			t.Error(err)
			continue
		}
		iv, err := enc1.GenerateIV()
		if err != nil {
			t.Error(err)
			continue
		}

		if want, got := len(iv), enc.IVSize(); want != got {
			t.Errorf("%s: IVSize is mismatch: want %d, got %d", enc.String(), want, got)
		}
		if want, got := len(cek), enc.CEKSize(); want != got {
			t.Errorf("%s: CEKSize is mismatch: want %d, got %d", enc.String(), want, got)
		}
	}
}

func TestGenerateIV(t *testing.T) {
	enc := &algorithm{
		keyLen: 16,
	}

	iv0, err := enc.GenerateIV()
	if err != nil {
		t.Fatal(err)
	}
	iv1, err := enc.GenerateIV()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(iv0, iv1) {
		t.Errorf("iv must not match: %024x, %024x", iv0, iv1)
	}

	enc.counter = math.MaxUint64
	_, err = enc.GenerateIV()
	if err == nil {
		t.Error("want some error, but got nil")
	}

	if _, err := enc.GenerateCEK(); err != nil {
		t.Fatal(err)
	}

	iv2, err := enc.GenerateIV()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(iv0, iv2) {
		t.Errorf("iv must not match: %024x, %024x", iv0, iv2)
	}
}
