package secp256k1

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestVerify(t *testing.T) {
	// openssl ecparam -genkey -name secp256k1 -out privkey.pem
	// openssl ec -text -noout -in privkey.pem
	pub := &ecdsa.PublicKey{
		Curve: Curve(),
		X:     bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14"),
		Y:     bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb"),
	}

	// touch plaintext
	// openssl dgst -sha256 -sign privkey.pem plain.txt > sig.txt
	// openssl asn1parse -inform DER -in sig.txt
	message := []byte{}
	sum := sha256.Sum256(message)
	r := bigHex("3D2FCB610B176153D7740A300A6DE321D997D867308F6AF594D9B56EDDDBC918")
	s := bigHex("4EF2905C03EEDA8BC8D5C2464B62AA9C38F7BA0076FFBD25A8F29A4FF410116D")
	if !ecdsa.Verify(pub, sum[:], r, s) {
		t.Error("verify failed")
	}
}

func TestSign(t *testing.T) {
	// openssl ecparam -genkey -name secp256k1 -out privkey.pem
	// openssl ec -text -noout -in privkey.pem
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: Curve(),
			X:     bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14"),
			Y:     bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb"),
		},
		D: bigHex("1fd03e67f8a0c70531ff1af306265831d156678f3843ece8d39e894f5c9176d7"),
	}

	message := []byte("hello secp256k1")
	sum := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}

	if !ecdsa.Verify(&priv.PublicKey, sum[:], r, s) {
		t.Error("verify failed")
	}
}

func BenchmarkVerify(b *testing.B) {
	// openssl ecparam -genkey -name secp256k1 -out privkey.pem
	// openssl ec -text -noout -in privkey.pem
	pub := &ecdsa.PublicKey{
		Curve: Curve(),
		X:     bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14"),
		Y:     bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb"),
	}

	// touch plaintext
	// openssl dgst -sha256 -sign privkey.pem plain.txt > sig.txt
	// openssl asn1parse -inform DER -in sig.txt
	message := []byte{}
	sum := sha256.Sum256(message)
	r := bigHex("3D2FCB610B176153D7740A300A6DE321D997D867308F6AF594D9B56EDDDBC918")
	s := bigHex("4EF2905C03EEDA8BC8D5C2464B62AA9C38F7BA0076FFBD25A8F29A4FF410116D")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ecdsa.Verify(pub, sum[:], r, s) {
			b.Error("verify failed")
		}
	}
}

func BenchmarkSign(b *testing.B) {
	// openssl ecparam -genkey -name secp256k1 -out privkey.pem
	// openssl ec -text -noout -in privkey.pem
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: Curve(),
			X:     bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14"),
			Y:     bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb"),
		},
		D: bigHex("1fd03e67f8a0c70531ff1af306265831d156678f3843ece8d39e894f5c9176d7"),
	}

	message := []byte("hello secp256k1")
	sum := sha256.Sum256(message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := ecdsa.Sign(rand.Reader, priv, sum[:])
		if err != nil {
			b.Fatal(err)
		}
	}
}
