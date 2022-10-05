package pbes2

import (
	"crypto/subtle"
	"testing"
)

type options struct {
	p2s []byte
	p2c int
}

func (opts *options) PBES2SaltInput() []byte {
	return opts.p2s
}

func (opts *options) PBES2Count() int {
	return opts.p2c
}

func TestWrap(t *testing.T) {
	// https://github.com/lestrrat-go/jwx
	// $ echo 'Hello World!' > payload.txt
	// $ jwx jwk generate --type oct --keysize 16 > oct.json
	// $ jwx jwe encrypt --key oct.json --key-encryption PBES2-HS256+A128KW --content-encryption A128GCM payload.txt
	p2s := []byte{
		131, 206, 249, 161, 154, 238, 39, 156, 163, 249, 10, 154,
	}
	p2c := 10000
	opts := &options{
		p2s: p2s,
		p2c: p2c,
	}
	oct := []byte{
		0xb8, 0xe9, 0xc9, 0x3b, 0x74, 0xf0, 0xb6, 0xb5,
		0x67, 0x03, 0xa4, 0x08, 0x2b, 0x0d, 0xf1, 0x5e,
	}
	cek := []byte{
		43, 247, 226, 56, 102, 91, 73, 24, 69, 240, 115, 174, 5, 163, 18, 170,
	}

	alg := NewHS256A128KW()
	key := alg.NewKeyWrapper(oct, nil)
	got, err := key.WrapKey(cek, opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x27, 0xfe, 0xe9, 0x52, 0xcc, 0x7a, 0x2a, 0x7d,
		0x74, 0xf8, 0x03, 0xde, 0x16, 0x71, 0x00, 0xbd,
		0xf1, 0x49, 0x85, 0x53, 0xbf, 0xc8, 0x61, 0x15,
	}
	if subtle.ConstantTimeCompare(want, got) == 0 {
		t.Errorf("want %#v, got %#v", want, got)
	}
}

func TestUnrap(t *testing.T) {
	// https://github.com/lestrrat-go/jwx
	// $ echo 'Hello World!' > payload.txt
	// $ jwx jwk generate --type oct --keysize 16 > oct.json
	// $ jwx jwe encrypt --key oct.json --key-encryption PBES2-HS256+A128KW --content-encryption A128GCM payload.txt
	p2s := []byte{
		131, 206, 249, 161, 154, 238, 39, 156, 163, 249, 10, 154,
	}
	p2c := 10000
	opts := &options{
		p2s: p2s,
		p2c: p2c,
	}
	oct := []byte{
		0xb8, 0xe9, 0xc9, 0x3b, 0x74, 0xf0, 0xb6, 0xb5,
		0x67, 0x03, 0xa4, 0x08, 0x2b, 0x0d, 0xf1, 0x5e,
	}
	data := []byte{
		0x27, 0xfe, 0xe9, 0x52, 0xcc, 0x7a, 0x2a, 0x7d,
		0x74, 0xf8, 0x03, 0xde, 0x16, 0x71, 0x00, 0xbd,
		0xf1, 0x49, 0x85, 0x53, 0xbf, 0xc8, 0x61, 0x15,
	}

	alg := NewHS256A128KW()
	key := alg.NewKeyWrapper(oct, nil)
	got, err := key.UnwrapKey(data, opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		43, 247, 226, 56, 102, 91, 73, 24, 69, 240, 115, 174, 5, 163, 18, 170,
	}
	if subtle.ConstantTimeCompare(want, got) == 0 {
		t.Errorf("want %#v, got %#v", want, got)
	}
}
