package dir

import (
	"crypto"
	"testing"
)

type rawKey []byte

func (k rawKey) PrivateKey() crypto.PrivateKey {
	return []byte(k)
}

func (k rawKey) PublicKey() crypto.PublicKey {
	return nil
}

func TestWrapKey(t *testing.T) {
	alg := New()
	kw := alg.NewKeyWrapper(rawKey("foo bar"))
	data, err := kw.WrapKey([]byte{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Errorf("invalid data: %#v", data)
	}
}

func TestUnwrapKey(t *testing.T) {
	alg := New()
	kw := alg.NewKeyWrapper(rawKey("foo bar"))
	data, err := kw.UnwrapKey([]byte{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "foo bar" {
		t.Errorf("invalid data: %#v", data)
	}
}
