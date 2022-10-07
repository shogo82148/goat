package none

import (
	"bytes"
	"crypto"
	"testing"
)

type dummyKey struct{}

func (k *dummyKey) PrivateKey() crypto.PrivateKey { return nil }
func (k *dummyKey) PublicKey() crypto.PublicKey   { return nil }

func TestSign(t *testing.T) {
	alg := New()
	key := alg.NewSigningKey(nil)
	got, err := key.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{}
	if !bytes.Equal(want, got) {
		t.Errorf("signature mismatch: want [%x], got [%x]", want, got)
	}
}

func TestSign_InvalidKey(t *testing.T) {
	alg := New()
	// only nil is accepted as private and public key.
	key := alg.NewSigningKey(&dummyKey{})
	_, err := key.Sign([]byte("payload"))
	if err == nil {
		t.Error("want error, got nil")
	}
}

func TestVerify(t *testing.T) {
	var err error
	alg := New()
	key := alg.NewSigningKey(nil)

	err = key.Verify([]byte("payload"), []byte{})
	if err != nil {
		t.Fatal(err)
	}

	err = key.Verify([]byte("payload"), []byte{'a'})
	if err == nil {
		t.Error("want error, got nil")
	}
}

func TestVerify_InvalidKey(t *testing.T) {
	var err error
	alg := New()
	key := alg.NewSigningKey(&dummyKey{})

	err = key.Verify([]byte("payload"), []byte{})
	if err == nil {
		t.Error("want error, got nil")
	}
}
