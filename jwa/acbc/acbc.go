// package acbc provides AES_CBC_HMAC_SHA2 Algorithms.
package acbc

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"github.com/shogo82148/goat/enc"
	"github.com/shogo82148/goat/jwa"
)

var a128cbc_hs256 = &Algorithm{
	encKeyLen: 16,
	macKeyLen: 16,
	hash:      crypto.SHA256,
	tLen:      16,
}

func New128CBC_HS256() enc.Algorithm {
	return a128cbc_hs256
}

var a192cbc_hs384 = &Algorithm{
	encKeyLen: 24,
	macKeyLen: 24,
	hash:      crypto.SHA384,
	tLen:      24,
}

func New192CBC_HS384() enc.Algorithm {
	return a192cbc_hs384
}

var a256cbc_hs512 = &Algorithm{
	encKeyLen: 32,
	macKeyLen: 32,
	hash:      crypto.SHA512,
	tLen:      32,
}

func New256CBC_HS512() enc.Algorithm {
	return a256cbc_hs512
}

func init() {
	jwa.RegisterEncryptionAlgorithm(jwa.A128CBC_HS256, New128CBC_HS256)
	jwa.RegisterEncryptionAlgorithm(jwa.A192CBC_HS384, New192CBC_HS384)
	jwa.RegisterEncryptionAlgorithm(jwa.A256CBC_HS512, New256CBC_HS512)
}

var _ enc.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	encKeyLen int
	macKeyLen int
	hash      crypto.Hash
	tLen      int
}

func (alg *Algorithm) GenerateCEK() ([]byte, error) {
	cek := make([]byte, alg.encKeyLen+alg.macKeyLen)
	_, err := rand.Read(cek)
	if err != nil {
		return nil, err
	}
	return cek, nil
}

func (alg *Algorithm) GenerateIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}

func (alg *Algorithm) Decrypt(cek, iv, aad, ciphertext, authTag []byte) (plaintext []byte, err error) {
	if len(cek) != alg.macKeyLen+alg.encKeyLen {
		return nil, errors.New("acbc: invalid content encryption key")
	}
	mac := cek[:alg.macKeyLen]
	enc := cek[alg.macKeyLen:]
	plaintext = make([]byte, len(ciphertext))

	// decrypt
	block, err := aes.NewCipher(enc)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	size := block.BlockSize()
	if len(ciphertext)%size != 0 {
		return nil, errors.New("acbc: invalid size of ciphertext")
	}
	for i := 0; i <= len(ciphertext)-size; i += size {
		mode.CryptBlocks(plaintext[i:i+size], ciphertext[i:i+size])
	}
	toRemove, good := extractPadding(plaintext)

	// check the authentication tag
	expectedAuthTag := alg.calcAuthTag(mac, aad, iv, ciphertext)
	cmp := subtle.ConstantTimeCompare(authTag, expectedAuthTag) & int(good)
	if cmp != 1 {
		return nil, errors.New("acbc: authentication tag mismatch")
	}
	plaintext = plaintext[:len(plaintext)-toRemove]

	return
}

func (alg *Algorithm) Encrypt(cek, iv, aad, plaintext []byte) (ciphertext, authTag []byte, err error) {
	mac := cek[:alg.macKeyLen]
	enc := cek[alg.macKeyLen:]
	block, err := aes.NewCipher(enc)
	if err != nil {
		return nil, nil, err
	}

	// encrypt
	size := block.BlockSize()
	ciphertext = padding(plaintext, size)
	mode := cipher.NewCBCEncrypter(block, iv)
	for i := 0; i <= len(ciphertext)-size; i += size {
		mode.CryptBlocks(ciphertext[i:i+size], ciphertext[i:i+size])
	}
	authTag = alg.calcAuthTag(mac, aad, iv, ciphertext)

	return
}

// ref. https://github.com/golang/go/blob/ebaa5ff39ee4046f7f94bf34a6e05702286b08d2/src/crypto/tls/conn.go#L269-L317
//
// extractPadding returns, in constant time, the length of the padding to remove
// from the end of payload. It also returns a byte which is equal to 255 if the
// padding was valid and 0 otherwise. See RFC 2246, Section 6.2.3.2.
func extractPadding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)) - uint(paddingLen)
	// if len(payload) > paddingLen then the MSB of t is zero
	good = byte(int32(^t) >> 31)

	// The maximum possible padding length plus the actual length field
	toCheck := 256
	// The length of the padded data is public, so we can use an if here
	if toCheck > len(payload) {
		toCheck = len(payload)
	}

	for i := 1; i <= toCheck; i++ {
		t := uint(paddingLen) - uint(i)
		// if i <= paddingLen then the MSB of t is zero
		mask := byte(int32(^t) >> 31)
		b := payload[len(payload)-i]
		good &^= mask&paddingLen ^ mask&b
	}

	// We AND together the bits of good and replicate the result across
	// all the bits.
	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)

	// Zero the padding length on error. This ensures any unchecked bytes
	// are included in the MAC. Otherwise, an attacker that could
	// distinguish MAC failures from padding failures could mount an attack
	// similar to POODLE in SSL 3.0: given a good ciphertext that uses a
	// full block's worth of padding, replace the final block with another
	// block. If the MAC check passed but the padding check failed, the
	// last byte of that block decrypted to the block size.
	//
	// See also macAndPaddingGood logic below.
	paddingLen &= good

	toRemove = int(paddingLen)
	return
}

func padding(data []byte, size int) []byte {
	// calculate padding len
	l := len(data)
	paddingLen := size - (l % size)
	pad := byte(paddingLen)
	l += paddingLen
	ret := make([]byte, l)

	// fill pad
	copy(ret, data)
	for i := len(data); i < l; i++ {
		ret[i] = pad
	}
	return ret
}

func (alg *Algorithm) calcAuthTag(mac, aad, iv, ciphertext []byte) []byte {
	w := hmac.New(alg.hash.New, mac)
	w.Write(aad)
	w.Write(iv)
	w.Write(ciphertext)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(len(aad))*8)
	w.Write(buf[:])
	return w.Sum(nil)[:alg.tLen]
}
