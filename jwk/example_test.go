package jwk_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/shogo82148/goat/jwk"
)

func ExampleParseKey() {
	raw := `{"kty":"OKP","crv":"Ed25519",
		"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
		"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	key, err := jwk.ParseKey([]byte(raw))
	if err != nil {
		log.Fatal(err)
	}

	priv := key.PrivateKey().(ed25519.PrivateKey)
	fmt.Printf("%064x", priv.Seed())
	// Output:
	// 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
}

func ExampleParseMap() {
	raw := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"d":   "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
		"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
	}
	key, err := jwk.ParseMap(raw)
	if err != nil {
		log.Fatal(err)
	}

	priv := key.PrivateKey().(ed25519.PrivateKey)
	fmt.Printf("%064x", priv.Seed())
	// Output:
	// 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
}

func ExampleNewPrivateKey() {
	// generate a new private key of Ed25519.
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		log.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	// generate a new JWK from ed25519.PrivateKey.
	key, err := jwk.NewPrivateKey(priv)
	if err != nil {
		log.Fatal(err)
	}

	data, err := key.MarshalJSON()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))
	// Output:
	// {"crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
}

func ExampleNewPublicKey() {
	// generate a new private key of Ed25519.
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		log.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	// generate a new JWK from ed25519.PublicKey.
	key, err := jwk.NewPublicKey(priv.Public())
	if err != nil {
		log.Fatal(err)
	}

	data, err := key.MarshalJSON()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))
	// Output:
	// {"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
}

func ExampleDecodePEM() {
	ed25519PrivateKey := `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKwAUfUUia9rBpRD+sgNlTI5n5RhwMNDaaWFN5Kl3tiF
-----END PRIVATE KEY-----
and some more`

	key, _, err := jwk.DecodePEM([]byte(ed25519PrivateKey))
	if err != nil {
		log.Fatal(err)
	}

	priv := key.PrivateKey().(ed25519.PrivateKey)
	fmt.Printf("%064x", priv.Seed())
	// Output:
	// ac0051f51489af6b069443fac80d9532399f9461c0c34369a5853792a5ded885
}
