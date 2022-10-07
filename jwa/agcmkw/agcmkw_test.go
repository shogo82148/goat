package agcmkw

import (
	"crypto"
	"crypto/subtle"
	"testing"
)

type options struct {
	iv  []byte
	tag []byte
}

func (opts *options) InitializationVector() []byte {
	return opts.iv
}

func (opts *options) SetInitializationVector(iv []byte) {
	opts.iv = iv
}

func (opts *options) AuthenticationTag() []byte {
	return opts.tag
}

func (opts *options) SetAuthenticationTag(tag []byte) {
	opts.tag = tag
}

type bytesKey []byte

func (k bytesKey) PrivateKey() crypto.PrivateKey {
	return []byte(k)
}

func (k bytesKey) PublicKey() crypto.PublicKey {
	return nil
}

func TestWrap(t *testing.T) {
	alg := New128()
	key := alg.NewKeyWrapper(bytesKey([]byte{
		0xb8, 0xe9, 0xc9, 0x3b, 0x74, 0xf0, 0xb6, 0xb5,
		0x67, 0x03, 0xa4, 0x08, 0x2b, 0x0d, 0xf1, 0x5e,
	}))
	opts := &options{
		iv: []byte{0x83, 0xce, 0xf9, 0xa1, 0x9a, 0xee, 0x27, 0x9c, 0xa3, 0xf9, 0xa, 0x9a},
	}
	data := []byte{0x7f, 0xe4, 0x7f, 0xc6, 0x1d, 0x18, 0xc3, 0xa9, 0xdf, 0x63, 0x27, 0xa3, 0x4e, 0x42, 0x55, 0xf4}

	got, err := key.WrapKey(data, opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xb7, 0xda, 0x77, 0xb8, 0x25, 0x8c, 0x8c, 0x1, 0xa9, 0x16, 0xb5, 0x84, 0x70, 0xe5, 0x8f, 0x41}
	if subtle.ConstantTimeCompare(want, got) == 0 {
		t.Errorf("want %#v, got %#v", want, got)
	}
	tag := []byte{0xe7, 0x9a, 0x82, 0x71, 0x41, 0x2c, 0x62, 0xf9, 0xf7, 0x52, 0x58, 0xa7, 0x9b, 0x23, 0x6c, 0x91}
	if subtle.ConstantTimeCompare(opts.tag, tag) == 0 {
		t.Errorf("want %#v, got %#v", tag, opts.tag)
	}
}

func TestUnwrap(t *testing.T) {
	alg := New128()
	key := alg.NewKeyWrapper(bytesKey([]byte{
		0xb8, 0xe9, 0xc9, 0x3b, 0x74, 0xf0, 0xb6, 0xb5,
		0x67, 0x03, 0xa4, 0x08, 0x2b, 0x0d, 0xf1, 0x5e,
	}))
	opts := &options{
		iv:  []byte{0x83, 0xce, 0xf9, 0xa1, 0x9a, 0xee, 0x27, 0x9c, 0xa3, 0xf9, 0xa, 0x9a},
		tag: []byte{0xe7, 0x9a, 0x82, 0x71, 0x41, 0x2c, 0x62, 0xf9, 0xf7, 0x52, 0x58, 0xa7, 0x9b, 0x23, 0x6c, 0x91},
	}
	data := []byte{0xb7, 0xda, 0x77, 0xb8, 0x25, 0x8c, 0x8c, 0x1, 0xa9, 0x16, 0xb5, 0x84, 0x70, 0xe5, 0x8f, 0x41}

	got, err := key.UnwrapKey(data, opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x7f, 0xe4, 0x7f, 0xc6, 0x1d, 0x18, 0xc3, 0xa9, 0xdf, 0x63, 0x27, 0xa3, 0x4e, 0x42, 0x55, 0xf4}
	if subtle.ConstantTimeCompare(want, got) == 0 {
		t.Errorf("want %#v, got %#v", want, got)
	}
}
