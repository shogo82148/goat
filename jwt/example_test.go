package jwt_test

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"time"

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

func ExampleClaims_DecodeCustom() {
	claims := new(jwt.Claims)
	claims.Raw = map[string]any{
		"string": "it is custom claim",
		"bytes":  "YmFzZTY0LXJhd3VybCBlbmNvZGVkIGJ5dGUgc2VxdWVuY2U",
		"time":   json.Number("1234567890"),
		"bigint": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
	}

	var myClaims struct {
		String string    `jwt:"string"`
		Bytes  []byte    `jwt:"bytes"`
		Time   time.Time `jwt:"time"`
		BigInt *big.Int  `jwt:"bigint"`
	}
	if err := claims.DecodeCustom(&myClaims); err != nil {
		log.Fatal(err)
	}

	fmt.Println(myClaims.String)
	fmt.Println(string(myClaims.Bytes))
	fmt.Println(myClaims.Time)
	fmt.Println(myClaims.BigInt)
	// Output:
	// it is custom claim
	// base64-rawurl encoded byte sequence
	// 2009-02-13 23:31:30 +0000 UTC
	// 71185727259945196030657158393116523760833600269775786460544228200423405551456
}

func ExampleClaims_EncodeCustom() {
	claims := new(jwt.Claims)

	var myClaims struct {
		String string    `jwt:"string"`
		Bytes  []byte    `jwt:"bytes"`
		Time   time.Time `jwt:"time"`
		BigInt *big.Int  `jwt:"bigint"`
	}
	myClaims.String = "it is custom claim"
	myClaims.Bytes = []byte("base64-rawurl encoded byte sequence")
	myClaims.Time = time.Unix(1234567890, 0)
	myClaims.BigInt, _ = new(big.Int).SetString("71185727259945196030657158393116523760833600269775786460544228200423405551456", 0)
	if err := claims.EncodeCustom(myClaims); err != nil {
		log.Fatal(err)
	}

	fmt.Println(claims.Raw["string"])
	fmt.Println(claims.Raw["bytes"])
	fmt.Println(claims.Raw["time"])
	fmt.Println(claims.Raw["bigint"])
	// Output:
	// it is custom claim
	// YmFzZTY0LXJhd3VybCBlbmNvZGVkIGJ5dGUgc2VxdWVuY2U
	// 1234567890
	// nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A
}
