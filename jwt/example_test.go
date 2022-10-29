package jwt_test

import (
	"fmt"
	"log"

	"github.com/shogo82148/goat/jwa"
	_ "github.com/shogo82148/goat/jwa/eddsa" // for jwa.EdDSA
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/jws"
	"github.com/shogo82148/goat/jwt"
)

func ExampleParse() {
	// prepare signing key.
	raw := `{"crv":"Ed25519","kty":"OKP","x":"BFfXRkBCOZGnrRClfKmI3fH_fgnvG_HF71tPkHHtdFw"}`
	key, err := jwk.ParseKey([]byte(raw))
	if err != nil {
		log.Fatal(err)
	}

	data := "eyJhbGciOiJFZERTQSJ9." +
		"eyJpc3MiOiJodHRwczovL2dpdGh1Yi5jb20vc2hvZ284MjE0OC9nb2F0In0." +
		"40CbHAJKHO_wM6YdpXjrK6b4duHoD14e9fyrUxUvOVGGK_lOCkQCfR0eJWYwLhUwAATHFTI0ppkh1cBidC8DDQ"
	finder := &jwt.JWKKeyFiner{Key: key}
	token, err := jwt.Parse([]byte(data), finder)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token.Claims.Issuer)

	// Output:
	// https://github.com/shogo82148/goat
}

func ExampleSign() {
	// prepare signing key.
	raw := `{"crv":"Ed25519","d":"AEJRVb3JLIx7nYP3YGbdiEcmfiQs8ZO89Fpg4Iw7CX4",
		"kty":"OKP","x":"BFfXRkBCOZGnrRClfKmI3fH_fgnvG_HF71tPkHHtdFw"}`
	key, err := jwk.ParseKey([]byte(raw))
	if err != nil {
		log.Fatal(err)
	}
	signingKey := jwa.EdDSA.New().NewSigningKey(key)

	// prepare the header and the claims.
	header := new(jws.Header)
	header.SetAlgorithm(jwa.EdDSA)
	claims := new(jwt.Claims)
	claims.Issuer = "https://github.com/shogo82148/goat"

	// sign
	token, err := jwt.Sign(header, claims, signingKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(token))

	// Output:
	// eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL2dpdGh1Yi5jb20vc2hvZ284MjE0OC9nb2F0In0.40CbHAJKHO_wM6YdpXjrK6b4duHoD14e9fyrUxUvOVGGK_lOCkQCfR0eJWYwLhUwAATHFTI0ppkh1cBidC8DDQ
}
