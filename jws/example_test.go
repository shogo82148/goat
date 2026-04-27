package jws_test

import (
	"context"
	"fmt"
	"log"

	"github.com/shogo82148/goat/jwa"
	_ "github.com/shogo82148/goat/jwa/ed25519"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/jws"
)

func ExampleParseCompact() {
	rawKey := `{"kty":"OKP","crv":"Ed25519",` +
		`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	key, err := jwk.ParseKey([]byte(rawKey))
	if err != nil {
		log.Fatal(err)
	}
	v := &jws.Verifier{
		AlgorithmVerifier: jws.AllowedAlgorithms{jwa.SignatureAlgorithmEd25519},
		KeyFinder:         &jws.JWKKeyFinder{JWK: key},
	}

	raw := "eyJhbGciOiJFZDI1NTE5In0" +
		"." +
		"RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc" +
		"." +
		"UxhIYLHGg39NVCLpQAVD_UcfOmnGSCzLFZoXYkLiIbFccmOb_qObsgjzLKsfJw-4NlccUgvYrEHrRbNV0HcZAQ"

	msg, err := jws.ParseCompact([]byte(raw))
	if err != nil {
		log.Fatal(err)
	}

	_, _, payload, err := v.Verify(context.Background(), msg)
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
		AlgorithmVerifier: jws.AllowedAlgorithms{jwa.SignatureAlgorithmEd25519},
		KeyFinder:         &jws.JWKKeyFinder{JWK: key},
	}

	raw := "eyJhbGciOiJFZDI1NTE5In0" +
		"." +
		"RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc" +
		"." +
		"UxhIYLHGg39NVCLpQAVD_UcfOmnGSCzLFZoXYkLiIbFccmOb_qObsgjzLKsfJw-4NlccUgvYrEHrRbNV0HcZAQ"

	msg, err := jws.ParseCompact([]byte(raw))
	if err != nil {
		log.Fatal(err)
	}

	_, _, payload, err := v.Verify(context.Background(), msg)
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
	header.SetAlgorithm(jwa.SignatureAlgorithmEd25519)
	msg := jws.NewMessage([]byte("Example of Ed25519 signing"))
	if err := msg.Sign(header, nil, jwa.SignatureAlgorithmEd25519.New().NewSigningKey(key)); err != nil {
		log.Fatal(err)
	}

	data, err := msg.Compact()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))
	// Output:
	// eyJhbGciOiJFZDI1NTE5In0.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.UxhIYLHGg39NVCLpQAVD_UcfOmnGSCzLFZoXYkLiIbFccmOb_qObsgjzLKsfJw-4NlccUgvYrEHrRbNV0HcZAQ
}
