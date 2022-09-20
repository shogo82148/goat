package jwk

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/shogo82148/goat/jwa"
)

func TestParseKey_RFC7517AppendixA(t *testing.T) {
	t.Run("RFC 7517 A.1. Example Public Keys (EC)", func(t *testing.T) {
		rawKey := `{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
			`"use":"enc",` +
			`"kid":"1"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if want, got := key.KeyType, jwa.EC; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		x, _ := new(big.Int).SetString("21994169848703329112137818087919262246467304847122821377551355163096090930238", 10)
		y, _ := new(big.Int).SetString("101451294974385619524093058399734017814808930032421185206609461750712400090915", 10)
		publicKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
		if !publicKey.Equal(key.PublicKey) {
			t.Errorf("unexpected public key: want %v, got %v", publicKey, key.PublicKey)
		}
	})

	t.Run("RFC 7517 A.1. Example Public Keys (RSA)", func(t *testing.T) {
		rawKey := `{"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx` +
			`4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs` +
			`tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2` +
			`QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI` +
			`SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb` +
			`w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e":"AQAB",` +
			`"alg":"RS256",` +
			`"kid":"2011-04-29"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if want, got := jwa.RSA, key.KeyType; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		if want, got := key.Algorithm, jwa.RS256.KeyAlgorithm(); want != got {
			t.Errorf("unexpected algorithm: want %s, got %s", want, got)
		}
		n, _ := new(big.Int).SetString("2663454760017700891236544146403688261110463413643058169610263946307526643621694631605384564230016632"+
			"0042915031924501272705275043130211783228252369194856949397782880847235143381529207382262647906987655"+
			"73864738700732036114985476652341729332373918530811337352951272893283810014161204871259717869572065134"+
			"42954501748953699233833967043343316272615659072667498637447079206063646782316391064038549773021837192"+
			"46256958550651555767664134467706614553219592981545363271425781391262006405169505726523023628770285432"+
			"06204439131004744574928756316166854835432256022350994699082769165462796818216782639701536883643596535"+
			"4956581554819", 10)
		publicKey := &rsa.PublicKey{
			N: n,
			E: 65537,
		}
		if !publicKey.Equal(key.PublicKey) {
			t.Errorf("unexpected public key: want %v, got %v", publicKey, key.PublicKey)
		}
	})

	t.Run("RFC 7517 A.2. Example Private Keys (EC)", func(t *testing.T) {
		rawKey := `{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
			`"d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",` +
			`"use":"enc",` +
			`"kid":"1"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if want, got := key.KeyType, jwa.EC; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		x, _ := new(big.Int).SetString("21994169848703329112137818087919262246467304847122821377551355163096090930238", 10)
		y, _ := new(big.Int).SetString("101451294974385619524093058399734017814808930032421185206609461750712400090915", 10)
		publicKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
		if !publicKey.Equal(key.PublicKey) {
			t.Errorf("unexpected public key: want %v, got %v", publicKey, key.PublicKey)
		}

		d, _ := new(big.Int).SetString("110246039328358150430804407946042381407500908316371398015658902487828646033409", 10)
		privateKey := &ecdsa.PrivateKey{
			PublicKey: *publicKey,
			D:         d,
		}
		if !privateKey.Equal(key.PrivateKey) {
			t.Errorf("unexpected private key: want %v, got %v", privateKey, key.PrivateKey)
		}
	})

	t.Run("RFC 7517 A.2. Example Private Keys (RSA)", func(t *testing.T) {
		rawKey := `{"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4` +
			`cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst` +
			`n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q` +
			`vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS` +
			`D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw` +
			`0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e":"AQAB",` +
			`"d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9` +
			`M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij` +
			`wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d` +
			`_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz` +
			`nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz` +
			`me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",` +
			`"p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV` +
			`nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV` +
			`WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",` +
			`"q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum` +
			`qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx` +
			`kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",` +
			`"dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim` +
			`YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu` +
			`YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",` +
			`"dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU` +
			`vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9` +
			`GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",` +
			`"qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg` +
			`UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx` +
			`yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",` +
			`"alg":"RS256",` +
			`"kid":"2011-04-29"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if want, got := jwa.RSA, key.KeyType; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		if want, got := key.Algorithm, jwa.RS256.KeyAlgorithm(); want != got {
			t.Errorf("unexpected algorithm: want %s, got %s", want, got)
		}
		n, _ := new(big.Int).SetString("2663454760017700891236544146403688261110463413643058169610263946307526643621694631605384564230016632"+
			"0042915031924501272705275043130211783228252369194856949397782880847235143381529207382262647906987655"+
			"7386473870073203611498547665234172933237391853081133735295127289328381001416120487125971786957206513"+
			"4429545017489536992338339670433433162726156590726674986374470792060636467823163910640385497730218371"+
			"9246256958550651555767664134467706614553219592981545363271425781391262006405169505726523023628770285"+
			"4320620443913100474457492875631616685483543225602235099469908276916546279681821678263970153688364359"+
			"65354956581554819", 10)
		d, _ := new(big.Int).SetString("1205924792010699887783419663033654909012172984314669042935217695023929049181173151099784490812781841"+
			"1197238472043208054457537365988720482227320941622579462890892342087370621321697913707583190432031443"+
			"4400855076471034236599118129766294054472330568327455961173265667580771922044349653088926268129166560"+
			"4680224733118493889676917405444969435539120561957451257170076749196209492833793684713066036505024032"+
			"0266640217014023576113710333420737911211020431514635349872426319659058955767361242629552548559609520"+
			"9250239693987467160268538071114762536941890338060376240915365022247952785727275762792243496244276444"+
			"39187009145144049", 10)
		p, _ := new(big.Int).SetString("1709716162470668866499493007324007203452104096583274606252645690601955703560752559950003264349576489"+
			"3338954980677028062326304665191493753361894062714674902466314905649296905373534893139842453957972444"+
			"4098289604654242233173575809842449568201338389043642401230443496229062531480383139022143795969631711"+
			"734885883", 10)
		q, _ := new(big.Int).SetString("1557834463101061046350991609467843638214148536549655504962072350640481549178747827741564860758056504"+
			"5759300741718852582504569725286722264440036104911664913190097222318670745302871713220098810850986141"+
			"3777141915906732412234602566205784553888885870066323934623297601869512681652807048545792342297108375"+
			"492531993", 10)
		privateKey := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: n,
				E: 65537,
			},
			D:      d,
			Primes: []*big.Int{p, q},
		}
		publicKey := &rsa.PublicKey{
			N: n,
			E: 65537,
		}
		if !privateKey.Equal(key.PrivateKey) {
			t.Errorf("unexpected private key: want %v, got %v", privateKey, key.PrivateKey)
		}
		if !publicKey.Equal(key.PublicKey) {
			t.Errorf("unexpected public key: want %v, got %v", publicKey, key.PublicKey)
		}
	})

	t.Run("RFC 7517 A.3. Example Symmetric Keys (A128KW)", func(t *testing.T) {
		rawKey := `{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType != jwa.Oct {
			t.Errorf("unexpected key type: want %s, got %s", "oct", key.KeyType)
		}
		if key.Algorithm != "A128KW" {
			t.Errorf("unexpected algorithm: want %s, got %s", "A128KW", key.Algorithm)
		}
		got, ok := key.PrivateKey.([]byte)
		if !ok {
			t.Errorf("unexpected key type: want []byte, got %T", key.PublicKey)
		}
		want := []byte{
			0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5,
			0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52,
		}
		if !bytes.Equal(want, got) {
			t.Errorf("unexpected key value: want %x, got %x", want, got)
		}
	})

	t.Run("RFC 7517 A.3. Example Symmetric Keys (HMAC)", func(t *testing.T) {
		rawKey := `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","kid":"HMAC key used in JWS spec Appendix A.1 example"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType != jwa.Oct {
			t.Errorf("unexpected key type: want %s, got %s", "oct", key.KeyType)
		}
		got, ok := key.PrivateKey.([]byte)
		if !ok {
			t.Errorf("unexpected key type: want []byte, got %T", key.PublicKey)
		}
		want := []byte{
			0x03, 0x23, 0x35, 0x4b, 0x2b, 0x0f, 0xa5, 0xbc,
			0x83, 0x7e, 0x06, 0x65, 0x77, 0x7b, 0xa6, 0x8f,
			0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28,
			0xa9, 0x0f, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf,
			0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x06, 0x47, 0xef,
			0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22,
			0x3d, 0x2e, 0x21, 0x72, 0x05, 0x2e, 0x4f, 0x08,
			0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3,
		}
		if !bytes.Equal(want, got) {
			t.Errorf("unexpected key value: want %x, got %x", want, got)
		}
	})
}

func BenchmarkParseKey_RFC7517AppendixA(b *testing.B) {
	b.Run("RFC 7517 A.1. Example Public Keys (EC)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
			`"use":"enc",` +
			`"kid":"1"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RFC 7517 A.1. Example Public Keys (RSA)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx` +
			`4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs` +
			`tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2` +
			`QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI` +
			`SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb` +
			`w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e":"AQAB",` +
			`"alg":"RS256",` +
			`"kid":"2011-04-29"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RFC 7517 A.2. Example Private Keys (EC)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
			`"d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",` +
			`"use":"enc",` +
			`"kid":"1"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RFC 7517 A.2. Example Private Keys (RSA)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4` +
			`cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst` +
			`n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q` +
			`vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS` +
			`D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw` +
			`0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e":"AQAB",` +
			`"d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9` +
			`M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij` +
			`wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d` +
			`_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz` +
			`nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz` +
			`me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",` +
			`"p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV` +
			`nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV` +
			`WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",` +
			`"q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum` +
			`qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx` +
			`kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",` +
			`"dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim` +
			`YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu` +
			`YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",` +
			`"dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU` +
			`vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9` +
			`GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",` +
			`"qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg` +
			`UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx` +
			`yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",` +
			`"alg":"RS256",` +
			`"kid":"2011-04-29"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RFC 7517 A.3. Example Symmetric Keys (A128KW)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RFC 7517 A.3. Example Symmetric Keys (HMAC)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","kid":"HMAC key used in JWS spec Appendix A.1 example"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestParseKey_RFC7517AppendixB(t *testing.T) {
	// RFC7517 Appendix B. Example Use of "x5c" (X.509 Certificate Chain) Parameter
	rawKey := []byte(`{"kty":"RSA",` +
		`"use":"sig",` +
		`"kid":"1b94c",` +
		`"n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08` +
		`PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Q` +
		`u2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a` +
		`YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwH` +
		`MTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMv` +
		`VfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",` +
		`"e":"AQAB",` +
		`"x5c":` +
		`["MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJB` +
		`gNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYD` +
		`VQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1` +
		`wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBg` +
		`NVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDV` +
		`QQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1w` +
		`YmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnH` +
		`YMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66` +
		`s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6` +
		`SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpn` +
		`fajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPq` +
		`PvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVk` +
		`aZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BA` +
		`QUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL` +
		`+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1` +
		`zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL` +
		`2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo` +
		`4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTq` +
		`gawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="]` +
		`}`)
	key, err := ParseKey(rawKey)
	if err != nil {
		t.Fatal(err)
	}
	if key.KeyType != "RSA" {
		t.Errorf("unexpected key type: want %s, got %s", "RSA", key.KeyType)
	}
	if len(key.X509CertificateChain) != 1 {
		t.Errorf("unexpected certificate chain length: want 1, got %d", len(key.X509CertificateChain))
	}

	keyPublicKey := key.PublicKey.(*rsa.PublicKey)
	cert := key.X509CertificateChain[0]
	certPublicKey := cert.PublicKey.(*rsa.PublicKey)
	if !keyPublicKey.Equal(certPublicKey) {
		t.Error("public keys are missmatch")
	}
	issuer := "CN=Brian Campbell,O=Ping Identity Corp.,L=Denver,ST=CO,C=US"
	if cert.Issuer.String() != issuer {
		t.Errorf("unexpected issuer: want %q, got %q", issuer, cert.Issuer.String())
	}
}

func BenchmarkParseKey_RFC7517AppendixB(b *testing.B) {
	// RFC7517 Appendix B. Example Use of "x5c" (X.509 Certificate Chain) Parameter
	rawKey := []byte(`{"kty":"RSA",` +
		`"use":"sig",` +
		`"kid":"1b94c",` +
		`"n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08` +
		`PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Q` +
		`u2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a` +
		`YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwH` +
		`MTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMv` +
		`VfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",` +
		`"e":"AQAB",` +
		`"x5c":` +
		`["MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJB` +
		`gNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYD` +
		`VQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1` +
		`wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBg` +
		`NVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDV` +
		`QQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1w` +
		`YmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnH` +
		`YMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66` +
		`s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6` +
		`SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpn` +
		`fajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPq` +
		`PvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVk` +
		`aZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BA` +
		`QUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL` +
		`+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1` +
		`zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL` +
		`2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo` +
		`4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTq` +
		`gawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="]` +
		`}`)
	for i := 0; i < b.N; i++ {
		if _, err := ParseKey(rawKey); err != nil {
			b.Fatal(err)
		}
	}
}

func TestParseKey_RFC8037AppendixA(t *testing.T) {
	t.Run("A.1. Ed25519 Private Key", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"Ed25519",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType != jwa.OKP {
			t.Errorf("unexpected key type: want %s, got %s", "OKP", key.KeyType)
		}

		privateKey := ed25519.PrivateKey{
			0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
			0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
			0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
			0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
		}
		if !privateKey.Equal(key.PrivateKey) {
			t.Errorf("unexpected private key: want %v, got %v", privateKey, key.PrivateKey)
		}

		publicKey := ed25519.PublicKey{
			0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
			0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
		}
		if !publicKey.Equal(key.PublicKey) {
			t.Errorf("unexpected public key: want %x, got %x", publicKey, key.PublicKey)
		}
	})

	t.Run("A.2. Ed25519 Public Key", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"Ed25519",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType != jwa.OKP {
			t.Errorf("unexpected key type: want %s, got %s", "OKP", key.KeyType)
		}

		publicKey := ed25519.PublicKey{
			0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
			0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
		}
		if !publicKey.Equal(key.PublicKey) {
			t.Errorf("unexpected public key: want %x, got %x", publicKey, key.PublicKey)
		}
	})
}

func BenchmarkParseKey_RFC8037AppendixA(b *testing.B) {
	b.Run("A.1. Ed25519 Private Key", func(b *testing.B) {
		rawKey := []byte(`{"kty":"OKP","crv":"Ed25519",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("A.2. Ed25519 Public Key", func(b *testing.B) {
		rawKey := []byte(`{"kty":"OKP","crv":"Ed25519",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestKey_Base64Error(t *testing.T) {
	t.Run("EC Public Keys", func(t *testing.T) {
		rawKey := `{"kty":"EC",` +
			`"crv":"P-521",` +
			`"x":"!!!INVALID BASE64!!!",` +
			`"y":"!!!INVALID BASE64!!!",` +
			`"use":"enc",` +
			`"kid":"1"}`
		_, err := ParseKey([]byte(rawKey))
		if err == nil {
			t.Error("want not nil, got nil")
		}
	})

	t.Run("EC Private Keys", func(t *testing.T) {
		rawKey := `{"kty":"EC",` +
			`"crv":"P-521",` +
			`"x":"!!!INVALID BASE64!!!",` +
			`"y":"!!!INVALID BASE64!!!",` +
			`"d":"!!!INVALID BASE64!!!",` +
			`"use":"enc",` +
			`"kid":"1"}`
		_, err := ParseKey([]byte(rawKey))
		if err == nil {
			t.Error("want not nil, got nil")
		}
	})

	t.Run("RSA Public Key", func(t *testing.T) {
		rawKey := `{"kty":"RSA",` +
			`"n":"!!!INVALID BASE64!!!",` +
			`"e":"!!!INVALID BASE64!!!",` +
			`"alg":"RS256",` +
			`"kid":"2011-04-29"}`
		_, err := ParseKey([]byte(rawKey))
		if err == nil {
			t.Error("want not nil, got nil")
		}
	})

	t.Run("Symmetric Keys (HMAC)", func(t *testing.T) {
		rawKey := `{"kty":"oct","k":"!!!INVALID BASE64!!!"}`
		_, err := ParseKey([]byte(rawKey))
		if err == nil {
			t.Error("want not nil, got nil")
		}
	})

	t.Run("Ed25519 Public Key", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"Ed25519",` +
			`"x":"!!!INVALID BASE64!!!"}`
		_, err := ParseKey([]byte(rawKey))
		if err == nil {
			t.Error("want not nil, got nil")
		}
	})

	t.Run("Ed25519 Private Key", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"Ed25519",` +
			`"d":"!!!INVALID BASE64!!!",` +
			`"x":"!!!INVALID BASE64!!!"}`
		_, err := ParseKey([]byte(rawKey))
		if err == nil {
			t.Error("want not nil, got nil")
		}
	})
}

func TestMarshalKey_RFC7517AppendixA(t *testing.T) {
	t.Run("RFC 7517 A.1. Example Public Keys (EC)", func(t *testing.T) {
		x, _ := new(big.Int).SetString("21994169848703329112137818087919262246467304847122821377551355163096090930238", 10)
		y, _ := new(big.Int).SetString("101451294974385619524093058399734017814808930032421185206609461750712400090915", 10)
		key := &Key{
			KeyType:      jwa.EC,
			KeyID:        "1",
			PublicKeyUse: "enc",
			PublicKey: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			},
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"crv":"P-256",` +
			`"kid":"1",` +
			`"kty":"EC",` +
			`"use":"enc",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"` +
			`}`
		if string(got) != want {
			t.Errorf("want %q, got %q", want, got)
		}
	})

	t.Run("RFC 7517 A.1. Example Public Keys (RSA)", func(t *testing.T) {
		n, _ := new(big.Int).SetString("2663454760017700891236544146403688261110463413643058169610263946307526643621694631605384564230016632"+
			"0042915031924501272705275043130211783228252369194856949397782880847235143381529207382262647906987655"+
			"73864738700732036114985476652341729332373918530811337352951272893283810014161204871259717869572065134"+
			"42954501748953699233833967043343316272615659072667498637447079206063646782316391064038549773021837192"+
			"46256958550651555767664134467706614553219592981545363271425781391262006405169505726523023628770285432"+
			"06204439131004744574928756316166854835432256022350994699082769165462796818216782639701536883643596535"+
			"4956581554819", 10)
		key := &Key{
			Algorithm: jwa.RS256.KeyAlgorithm(),
			PublicKey: &rsa.PublicKey{
				N: n,
				E: 65537,
			},
			KeyID: "2011-04-29",
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"alg":"RS256",` +
			`"e":"AQAB",` +
			`"kid":"2011-04-29",` +
			`"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx` +
			`4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs` +
			`tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2` +
			`QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI` +
			`SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb` +
			`w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"` +
			`}`
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("want %q, got %q", want, got)
		}
	})

	t.Run("RFC 7517 A.2. Example Private Keys (EC)", func(t *testing.T) {
		x, _ := new(big.Int).SetString("21994169848703329112137818087919262246467304847122821377551355163096090930238", 10)
		y, _ := new(big.Int).SetString("101451294974385619524093058399734017814808930032421185206609461750712400090915", 10)
		d, _ := new(big.Int).SetString("110246039328358150430804407946042381407500908316371398015658902487828646033409", 10)
		key := &Key{
			PrivateKey: &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     x,
					Y:     y,
				},
				D: d,
			},
			PublicKey: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			},
			PublicKeyUse: "enc",
			KeyID:        "1",
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"crv":"P-256",` +
			`"d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",` +
			`"kid":"1",` +
			`"kty":"EC",` +
			`"use":"enc",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"` +
			`}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %q, got %q", want, got)
		}
	})

	t.Run("RFC 7517 A.2. Example Private Keys (RSA)", func(t *testing.T) {
		n, _ := new(big.Int).SetString("2663454760017700891236544146403688261110463413643058169610263946307526643621694631605384564230016632"+
			"0042915031924501272705275043130211783228252369194856949397782880847235143381529207382262647906987655"+
			"7386473870073203611498547665234172933237391853081133735295127289328381001416120487125971786957206513"+
			"4429545017489536992338339670433433162726156590726674986374470792060636467823163910640385497730218371"+
			"9246256958550651555767664134467706614553219592981545363271425781391262006405169505726523023628770285"+
			"4320620443913100474457492875631616685483543225602235099469908276916546279681821678263970153688364359"+
			"65354956581554819", 10)
		d, _ := new(big.Int).SetString("1205924792010699887783419663033654909012172984314669042935217695023929049181173151099784490812781841"+
			"1197238472043208054457537365988720482227320941622579462890892342087370621321697913707583190432031443"+
			"4400855076471034236599118129766294054472330568327455961173265667580771922044349653088926268129166560"+
			"4680224733118493889676917405444969435539120561957451257170076749196209492833793684713066036505024032"+
			"0266640217014023576113710333420737911211020431514635349872426319659058955767361242629552548559609520"+
			"9250239693987467160268538071114762536941890338060376240915365022247952785727275762792243496244276444"+
			"39187009145144049", 10)
		p, _ := new(big.Int).SetString("1709716162470668866499493007324007203452104096583274606252645690601955703560752559950003264349576489"+
			"3338954980677028062326304665191493753361894062714674902466314905649296905373534893139842453957972444"+
			"4098289604654242233173575809842449568201338389043642401230443496229062531480383139022143795969631711"+
			"734885883", 10)
		q, _ := new(big.Int).SetString("1557834463101061046350991609467843638214148536549655504962072350640481549178747827741564860758056504"+
			"5759300741718852582504569725286722264440036104911664913190097222318670745302871713220098810850986141"+
			"3777141915906732412234602566205784553888885870066323934623297601869512681652807048545792342297108375"+
			"492531993", 10)
		privateKey := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: n,
				E: 65537,
			},
			D:      d,
			Primes: []*big.Int{p, q},
		}
		privateKey.Precompute()
		publicKey := &rsa.PublicKey{
			N: n,
			E: 65537,
		}
		key := &Key{
			Algorithm:  jwa.RS256.KeyAlgorithm(),
			KeyID:      "2011-04-29",
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"alg":"RS256",` +
			`"d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9` +
			`M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij` +
			`wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d` +
			`_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz` +
			`nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz` +
			`me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",` +
			`"dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim` +
			`YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu` +
			`YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",` +
			`"dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU` +
			`vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9` +
			`GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",` +
			`"e":"AQAB",` +
			`"kid":"2011-04-29",` +
			`"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4` +
			`cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst` +
			`n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q` +
			`vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS` +
			`D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw` +
			`0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV` +
			`nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV` +
			`WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",` +
			`"q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum` +
			`qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx` +
			`kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",` +
			`"qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg` +
			`UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx` +
			`yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU"}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %s, got %s", want, got)
		}
	})

	t.Run("RFC 7517 A.3. Example Symmetric Keys (A128KW)", func(t *testing.T) {
		key := &Key{
			Algorithm: jwa.A128KW.KeyAlgorithm(),
			PrivateKey: []byte{
				0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5,
				0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52,
			},
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg","kty":"oct"}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %s, got %s", want, got)
		}
	})

	t.Run("RFC 7517 A.3. Example Symmetric Keys (HMAC)", func(t *testing.T) {
		key := &Key{
			KeyID: "HMAC key used in JWS spec Appendix A.1 example",
			PrivateKey: []byte{
				0x03, 0x23, 0x35, 0x4b, 0x2b, 0x0f, 0xa5, 0xbc,
				0x83, 0x7e, 0x06, 0x65, 0x77, 0x7b, 0xa6, 0x8f,
				0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28,
				0xa9, 0x0f, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf,
				0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x06, 0x47, 0xef,
				0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22,
				0x3d, 0x2e, 0x21, 0x72, 0x05, 0x2e, 0x4f, 0x08,
				0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3,
			},
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","kid":"HMAC key used in JWS spec Appendix A.1 example","kty":"oct"}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %s, got %s", want, got)
		}
	})
}

func TestMarshalKey_RFC8037AppendixA(t *testing.T) {
	t.Run("A.1. Ed25519 Private Key", func(t *testing.T) {
		key := &Key{
			PrivateKey: ed25519.PrivateKey{
				0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
				0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
				0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
				0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
			},
			PublicKey: ed25519.PublicKey{
				0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
				0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
			},
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"crv":"Ed25519",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"kty":"OKP",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %s, got %s", want, got)
		}
	})

	t.Run("A.2. Ed25519 Public Key", func(t *testing.T) {
		key := &Key{
			PublicKey: ed25519.PublicKey{
				0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
				0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
			},
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"crv":"Ed25519",` +
			`"kty":"OKP",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %s, got %s", want, got)
		}
	})
}
