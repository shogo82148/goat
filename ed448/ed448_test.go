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
		t.Errorf("want %0114x, got %0114x", seed, priv[:57])
	}
	if !bytes.Equal(priv[57:], pub) {
		t.Errorf("want %0114x, got %0114x", pub, priv[57:])
	}
}
