package jws_test

import (
	"context"
	"fmt"
	"log"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/jws"
)

func ExampleParse() {
	rawKey := `{"kty":"OKP","crv":"Ed25519",` +
		`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	key, err := jwk.ParseKey([]byte(rawKey))
	if err != nil {
		log.Fatal(err)
	}
	v := &jws.Verifier{
		AlgorithmVerifier: jws.AllowedAlgorithms{jwa.EdDSA},
		KeyFinder:         &jws.JWKKeyFinder{JWK: key},
	}

	raw := "eyJhbGciOiJFZERTQSJ9" +
		"." +
		"RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc" +
		"." +
		"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt" +
		"9g7sVvpAr_MuM0KAg"

	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		log.Fatal(err)
	}

	_, payload, err := v.Verify(context.Background(), msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(payload))
	// Output:
	// Example of Ed25519 signing
}

func ExampleVerifier_Verify() {
	rawKey := `{"kty":"OKP","crv":"Ed25519",` +
		`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	key, err := jwk.ParseKey([]byte(rawKey))
	if err != nil {
		log.Fatal(err)
	}
	v := &jws.Verifier{
		AlgorithmVerifier: jws.AllowedAlgorithms{jwa.EdDSA},
		KeyFinder:         &jws.JWKKeyFinder{JWK: key},
	}

	raw := "eyJhbGciOiJFZERTQSJ9" +
		"." +
		"RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc" +
		"." +
		"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt" +
		"9g7sVvpAr_MuM0KAg"

	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		log.Fatal(err)
	}

	_, payload, err := v.Verify(context.Background(), msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(payload))
	// Output:
	// Example of Ed25519 signing
}

func ExampleMessage_Compact() {
	rawKey := `{"kty":"OKP","crv":"Ed25519",` +
		`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
		`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	key, err := jwk.ParseKey([]byte(rawKey))
	if err != nil {
		log.Fatal(err)
	}
	header := jws.NewHeader()
	header.SetAlgorithm(jwa.EdDSA)
	msg := jws.NewMessage([]byte("Example of Ed25519 signing"))
	if err := msg.Sign(header, nil, jwa.EdDSA.New().NewSigningKey(key)); err != nil {
		log.Fatal(err)
	}

	data, err := msg.Compact()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))
	// Output:
	// eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg
}
