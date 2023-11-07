package jws

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/shogo82148/goat/jwa/eddsa" // for Ed25519
	_ "github.com/shogo82148/goat/jwa/es"    // for ECDSA
	_ "github.com/shogo82148/goat/jwa/hs"    // for HMAC SHA-256
	_ "github.com/shogo82148/goat/jwa/ps"    // for RSASSA-PKCS1-v1_5 SHA-256
	_ "github.com/shogo82148/goat/jwa/rs"    // for RSASSA-PKCS1-v1_5 SHA-256

	"github.com/shogo82148/goat/jwa"
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
	Key       any                    `json:"key"`
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
	files, err := filepath.Glob("../testdata/ietf-jose-cookbook/jws/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		file := file
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var tv testVector
			if err := json.Unmarshal(data, &tv); err != nil {
				t.Fatal(err)
			}

		})
	}

}
