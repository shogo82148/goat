package none

import (
	"bytes"
	"testing"
)

func TestSign(t *testing.T) {
	alg := New()
	key := alg.NewKey(nil, nil)
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
	key := alg.NewKey("invalid key", nil)
	_, err := key.Sign([]byte("payload"))
	if err == nil {
		t.Error("want error, got nil")
	}
}

func TestVerify(t *testing.T) {
	var err error
	alg := New()
	key := alg.NewKey(nil, nil)

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
	key := alg.NewKey("invalid", nil)

	err = key.Verify([]byte("payload"), []byte{})
	if err == nil {
		t.Error("want error, got nil")
	}
}
