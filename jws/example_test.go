package jws_test

// import (
// 	"fmt"
// 	"log"

// 	"github.com/shogo82148/goat/jwa"
// 	"github.com/shogo82148/goat/jwk"
// 	"github.com/shogo82148/goat/jws"
// 	"github.com/shogo82148/goat/sig"
// )

// func ExampleParse() {
// 	rawKey := `{"kty":"OKP","crv":"Ed25519",` +
// 		`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
// 	key, err := jwk.ParseKey([]byte(rawKey))
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	raw := "eyJhbGciOiJFZERTQSJ9" +
// 		"." +
// 		"RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc" +
// 		"." +
// 		"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt" +
// 		"9g7sVvpAr_MuM0KAg"

// 	msg, err := jws.Parse([]byte(raw))
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	_, payload, err := msg.Verify(jws.FindKeyFunc(func(header, _ *jws.Header) (sig.SigningKey, error) {
// 		alg := header.Algorithm().New()
// 		return alg.NewSigningKey(key), nil
// 	}))
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	fmt.Println(string(payload))
// 	// Output:
// 	// Example of Ed25519 signing
// }

// func ExampleMessage_Verify() {
// 	rawKey := `{"kty":"OKP","crv":"Ed25519",` +
// 		`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
// 	key, err := jwk.ParseKey([]byte(rawKey))
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	raw := "eyJhbGciOiJFZERTQSJ9" +
// 		"." +
// 		"RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc" +
// 		"." +
// 		"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt" +
// 		"9g7sVvpAr_MuM0KAg"

// 	msg, err := jws.Parse([]byte(raw))
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	_, payload, err := msg.Verify(jws.FindKeyFunc(func(header, _ *jws.Header) (sig.SigningKey, error) {
// 		alg := header.Algorithm().New()
// 		return alg.NewSigningKey(key), nil
// 	}))
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	fmt.Println(string(payload))
// 	// Output:
// 	// Example of Ed25519 signing
// }

// func ExampleMessage_Compact() {
// 	rawKey := `{"kty":"OKP","crv":"Ed25519",` +
// 		`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
// 		`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
// 	key, err := jwk.ParseKey([]byte(rawKey))
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	header := jws.NewHeader()
// 	header.SetAlgorithm(jwa.EdDSA)
// 	msg := jws.NewMessage([]byte("Example of Ed25519 signing"))
// 	if err := msg.Sign(header, nil, jwa.EdDSA.New().NewSigningKey(key)); err != nil {
// 		log.Fatal(err)
// 	}

// 	data, err := msg.Compact()
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	fmt.Println(string(data))
// 	// Output:
// 	// eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg
// }
