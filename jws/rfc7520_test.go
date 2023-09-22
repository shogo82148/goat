package jws

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/sig"
)

type testVector struct {
	Title        string             `json:"title"`
	Reproducible bool               `json:"reproducible"`
	Input        *testVectorInput   `json:"input"`
	Signing      *testVectorSigning `json:"signing"`
	Output       *testVectorOutput  `json:"output"`
}

type testVectorInput struct {
	Payload   string                 `json:"payload"`
	Key       *jwk.Key               `json:"key"`
	Algorithm jwa.SignatureAlgorithm `json:"alg"`
}

type testVectorSigning struct {
	Protected          *Header `json:"protected"`
	ProtectedBase64URL string  `json:"protected_b64u"`
	SignatureInput     string  `json:"sig-input"`
	Signature          string  `json:"sig"`
}

type testVectorOutput struct {
	Compact   string   `json:"compact"`
	JSON      *Message `json:"json"`
	Flattened *Message `json:"flattened"`
}

func TestRFC7520(t *testing.T) {
	t.Run("4.1. RSA v1.5 Signature", func(t *testing.T) {
		data, err := os.ReadFile("testdata/rfc7520/4_1.rsa_v15_signature.json")
		if err != nil {
			t.Fatal(err)
		}
		var tv testVector
		if err := json.Unmarshal(data, &tv); err != nil {
			t.Fatal(err)
		}

		// verify the signature of the compact serialization.
		msg, err := Parse([]byte(tv.Output.Compact))
		if err != nil {
			t.Fatal(err)
		}
		_, body, err := msg.Verify(FindKeyFunc(func(protected, unprotected *Header) (key sig.SigningKey, err error) {
			if protected.KeyID() != tv.Input.Key.KeyID() {
				return nil, errors.New("key not found")
			}
			alg := tv.Input.Algorithm.New()
			return alg.NewSigningKey(tv.Input.Key), nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != tv.Input.Payload {
			t.Errorf("unexpected payload: want %s, got %s", tv.Input.Payload, body)
		}

		// verify the signature of the JSON serialization.
		_, body, err = tv.Output.JSON.Verify(FindKeyFunc(func(protected, unprotected *Header) (key sig.SigningKey, err error) {
			if protected.KeyID() != tv.Input.Key.KeyID() {
				return nil, errors.New("key not found")
			}
			alg := tv.Input.Algorithm.New()
			return alg.NewSigningKey(tv.Input.Key), nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != tv.Input.Payload {
			t.Errorf("unexpected payload: want %s, got %s", tv.Input.Payload, body)
		}

		// TODO: verify the signature of the flattened serialization.
	})
}
