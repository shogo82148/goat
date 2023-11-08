package jws

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/shogo82148/goat/jwa"
	_ "github.com/shogo82148/goat/jwa/eddsa" // for Ed25519
	_ "github.com/shogo82148/goat/jwa/es"    // for ECDSA
	_ "github.com/shogo82148/goat/jwa/hs"    // for HMAC SHA-256
	_ "github.com/shogo82148/goat/jwa/ps"    // for RSASSA-PKCS1-v1_5 SHA-256
	_ "github.com/shogo82148/goat/jwa/rs"    // for RSASSA-PKCS1-v1_5 SHA-256
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/sig"

	"github.com/shogo82148/goat/internal/jsonutils"
)

type testVector struct {
	Title        string            `json:"title"`
	Reproducible bool              `json:"reproducible"`
	Input        *testVectorInput  `json:"input"`
	Signing      any               `json:"signing"`
	Output       *testVectorOutput `json:"output"`
}

type testVectorInput struct {
	Payload   string `json:"payload"`
	Key       any    `json:"key"`
	Algorithm any    `json:"alg"`
}

type testVectorOutput struct {
	Compact   string         `json:"compact"`
	JSON      map[string]any `json:"json"`
	Flattened map[string]any `json:"flattened"`
}

func TestRFC7520(t *testing.T) {
	files, err := filepath.Glob("../testdata/ietf-jose-cookbook/jws/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var tv testVector
		if err := jsonutils.Unmarshal(data, &tv); err != nil {
			t.Fatal(err)
		}

		t.Run(tv.Title, func(t *testing.T) {
			if keyMap, ok := tv.Input.Key.(map[string]any); ok {
				key, err := jwk.ParseMap(keyMap)
				if err != nil {
					t.Fatal(err)
				}
				alg := jwa.SignatureAlgorithm(tv.Input.Algorithm.(string))
				signingKey := alg.New().NewSigningKey(key)

				payload := []byte(tv.Input.Payload)

				if tv.Output.Compact != "" {
					t.Log("verifying compact serialization")
					msg, err := ParseCompact([]byte(tv.Output.Compact))
					if err != nil {
						t.Fatal(err)
					}
					v := &Verifier{
						KeyFinder: FindKeyFunc(func(ctx context.Context, protected, unprotected *Header) (sig.SigningKey, error) {
							return signingKey, nil
						}),
						AlgorithmVerifier: AllowedAlgorithms{alg},
					}

					var protected, unprotected *Header
					var got []byte
					if _, ok := tv.Output.JSON["payload"]; ok {
						protected, unprotected, got, err = v.Verify(context.Background(), msg)
					} else {
						protected, unprotected, got, err = v.VerifyContent(context.Background(), msg, payload)
					}
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, payload) {
						t.Errorf("payload mismatch: got %q, want %q", got, payload)
					}
					if unprotected != nil {
						// compact serialization doesn't have unprotected header
						t.Errorf("unprotected header should be nil")
					}
					if diff := cmp.Diff(protected.Raw, tv.Signing.(map[string]any)["protected"]); diff != "" {
						t.Errorf("protected header mismatch (-got +want):\n%s", diff)
					}
				}
			}
		})
	}
}
