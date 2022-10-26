package ed448

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func decodeHex(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func TestNewKeyFromSeed(t *testing.T) {
	seed := decodeHex(
		"6c82a562cb808d10d632be89c8513ebf" +
			"6c929f34ddfa8c9f63c9960ef6e348a3" +
			"528c8a3fcc2f044e39a3fc5b94492f8f" +
			"032e7549a20098f95b",
	)
	pub := decodeHex(
		"5fd7449b59b461fd2ce787ec616ad46a" +
			"1da1342485a70e1f8a0ea75d80e96778" +
			"edf124769b46c7061bd6783df1e50f6c" +
			"d1fa1abeafe8256180",
	)
	priv := NewKeyFromSeed(seed)
	if !bytes.Equal(priv[:57], seed) {
		t.Errorf("got %0114x, want %0114x", priv[:57], seed)
	}
	if !bytes.Equal(priv[57:], pub) {
		t.Errorf("got %0114x, want %0114x", priv[57:], pub)
	}
}

func TestSign(t *testing.T) {
	seed := decodeHex(
		"6c82a562cb808d10d632be89c8513ebf" +
			"6c929f34ddfa8c9f63c9960ef6e348a3" +
			"528c8a3fcc2f044e39a3fc5b94492f8f" +
			"032e7549a20098f95b",
	)
	want := decodeHex(
		"533a37f6bbe457251f023c0d88f976ae" +
			"2dfb504a843e34d2074fd823d41a591f" +
			"2b233f034f628281f2fd7a22ddd47d78" +
			"28c59bd0a21bfd3980ff0d2028d4b18a" +
			"9df63e006c5d1c2d345b925d8dc00b41" +
			"04852db99ac5c7cdda8530a113a0f4db" +
			"b61149f05a7363268c71d95808ff2e65" +
			"2600",
	)
	priv := NewKeyFromSeed(seed)
	signature := Sign(priv, []byte{})
	if !bytes.Equal(signature, want) {
		t.Errorf("got %0228x, want %0228x", signature, want)
	}
}
