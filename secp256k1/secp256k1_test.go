package secp256k1

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func decodeHex(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

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

	for i := 0; i < 1024; i++ {
		r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
		if err != nil {
			t.Fatal(err)
		}

		if !ecdsa.Verify(&priv.PublicKey, sum[:], r, s) {
			t.Error("verify failed")
		}
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

func TestIsOnCurve(t *testing.T) {
	x := bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14")
	y := bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb")
	crv := Curve()
	if !crv.IsOnCurve(x, y) {
		t.Error("(x,y) is not on curve")
	}
}

func BenchmarkIsOnCurve(b *testing.B) {
	x := bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14")
	y := bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb")
	crv := Curve()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crv.IsOnCurve(x, y)
	}
}

func TestAdd(t *testing.T) {
	x := bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14")
	y := bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb")
	gx := bigHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	gy := bigHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	crv := Curve()

	xx, yy := crv.Add(x, y, gx, gy)
	if xx.String() != "103398873363144253748994332925483235365773458200442655046283530549491799842290" {
		t.Errorf("want 103398873363144253748994332925483235365773458200442655046283530549491799842290, got %s", xx)
	}
	if yy.String() != "102711088724197372652192325011205002780277748253708500900510011110373995629577" {
		t.Errorf("want 102711088724197372652192325011205002780277748253708500900510011110373995629577, got %s", yy)
	}
}

func BenchmarkAdd(b *testing.B) {
	x := bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14")
	y := bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb")
	gx := bigHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	gy := bigHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	crv := Curve()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crv.Add(x, y, gx, gy)
	}
}

func TestDouble(t *testing.T) {
	x := bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14")
	y := bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb")
	crv := Curve()

	xx, yy := crv.Double(x, y)
	if xx.String() != "3253853896651542241016013980011516465233588677473825707395430701990395674578" {
		t.Errorf("want 3253853896651542241016013980011516465233588677473825707395430701990395674578, got %s", xx)
	}
	if yy.String() != "114598787363617463493329883950560025930749340347706847731863576152129383982080" {
		t.Errorf("want 114598787363617463493329883950560025930749340347706847731863576152129383982080, got %s", yy)
	}
}

func BenchmarkDouble(b *testing.B) {
	x := bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14")
	y := bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb")
	crv := Curve()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crv.Double(x, y)
	}
}

func TestScalarMult1(t *testing.T) {
	x := bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14")
	y := bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb")
	k, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	crv := Curve()

	xx, yy := crv.ScalarMult(x, y, k)
	if xx.String() != "55042608044612121400613053601674605111304023047002903551681986042062204131860" {
		t.Errorf("want 55042608044612121400613053601674605111304023047002903551681986042062204131860, got %s", xx)
	}
	if yy.String() != "95705376079305070156878129368455367607488344552125188713501476922294096330683" {
		t.Errorf("want 95705376079305070156878129368455367607488344552125188713501476922294096330683, got %s", yy)
	}
}

func TestScalarMultMinus1(t *testing.T) {
	x := bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14")
	y := bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb")
	k := decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
	crv := Curve()

	xx, yy := crv.ScalarMult(x, y, k)
	if xx.String() != "55042608044612121400613053601674605111304023047002903551681986042062204131860" {
		t.Errorf("want 55042608044612121400613053601674605111304023047002903551681986042062204131860, got %s", xx)
	}
	if yy.String() != "20086713158011125266692855640232540245781640113515375325956107085614738340980" {
		t.Errorf("want 20086713158011125266692855640232540245781640113515375325956107085614738340980, got %s", yy)
	}
}

func BenchmarkMult1(b *testing.B) {
	x := bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14")
	y := bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb")
	k := decodeHex("0000000000000000000000000000000000000000000000000000000000000001")
	crv := Curve()

	for i := 0; i < b.N; i++ {
		crv.ScalarMult(x, y, k)
	}
}

func BenchmarkMultMinus1(b *testing.B) {
	x := bigHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14")
	y := bigHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb")
	k := decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
	crv := Curve()

	for i := 0; i < b.N; i++ {
		crv.ScalarMult(x, y, k)
	}
}

func TestScalarBaseMult1(t *testing.T) {
	k, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	crv := Curve()

	xx, yy := crv.ScalarBaseMult(k)
	if xx.String() != "55066263022277343669578718895168534326250603453777594175500187360389116729240" {
		t.Errorf("want 55066263022277343669578718895168534326250603453777594175500187360389116729240, got %s", xx)
	}
	if yy.String() != "32670510020758816978083085130507043184471273380659243275938904335757337482424" {
		t.Errorf("want 32670510020758816978083085130507043184471273380659243275938904335757337482424, got %s", yy)
	}
}

func TestScalarBaseMultMinus1(t *testing.T) {
	k, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
	crv := Curve()

	xx, yy := crv.ScalarBaseMult(k)
	if xx.String() != "55066263022277343669578718895168534326250603453777594175500187360389116729240" {
		t.Errorf("want 55066263022277343669578718895168534326250603453777594175500187360389116729240, got %s", xx)
	}
	if yy.String() != "83121579216557378445487899878180864668798711284981320763518679672151497189239" {
		t.Errorf("want 83121579216557378445487899878180864668798711284981320763518679672151497189239, got %s", yy)
	}
}

func BenchmarkScalarBaseMult1(b *testing.B) {
	k, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	crv := Curve()

	for i := 0; i < b.N; i++ {
		crv.ScalarBaseMult(k)
	}
}

func BenchmarkScalarBaseMultMinus1(b *testing.B) {
	k, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
	crv := Curve()

	for i := 0; i < b.N; i++ {
		crv.ScalarBaseMult(k)
	}
}
