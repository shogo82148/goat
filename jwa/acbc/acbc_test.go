package acbc

import (
	"bytes"
	"crypto/subtle"
	"testing"

	"github.com/shogo82148/goat/jwa"
)

func TestDecrypt(t *testing.T) {
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
	enc := New128CBC_HS256()
	got, err := enc.Decrypt(cek, iv, aad, ciphertext, authTag)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
		112, 114, 111, 115, 112, 101, 114, 46,
	}

	if !bytes.Equal(want, got) {
		t.Errorf("want %#v, got %#v", want, got)
	}
}

func TestEncrypt(t *testing.T) {
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

	enc := New128CBC_HS256()
	ciphertext, authTag, err := enc.Encrypt(cek, iv, aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	wantCiphertext := []byte{
		40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
		75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
		112, 56, 102,
	}
	if subtle.ConstantTimeCompare(ciphertext, wantCiphertext) == 0 {
		t.Errorf("want %#v, got %#v", wantCiphertext, ciphertext)
	}

	wantAuthTag := []byte{
		246, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100,
		191,
	}
	if !bytes.Equal(authTag, wantAuthTag) {
		t.Errorf("want %#v, got %#v", wantAuthTag, authTag)
	}
}

func TestCEKSize_and_IVSize(t *testing.T) {
	tests := []jwa.EncryptionAlgorithm{
		jwa.A128CBC_HS256,
		jwa.A192CBC_HS384,
		jwa.A256CBC_HS512,
	}
	for _, enc := range tests {
		enc1 := enc.New()
		if want, got := enc1.IVSize(), enc.IVSize(); want != got {
			t.Errorf("%s: IVSize is mismatch: want %d, got %d", enc.String(), want, got)
		}
		if want, got := enc1.CEKSize(), enc.CEKSize(); want != got {
			t.Errorf("%s: CEKSize is mismatch: want %d, got %d", enc.String(), want, got)
		}
	}
}
