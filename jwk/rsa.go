package jwk

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
)

func parseRSAKey(d *jsonutils.Decoder, key *Key) {
	var privateKey rsa.PrivateKey

	// parameters for public key
	e := d.MustBigInt("e")
	if !e.IsInt64() || e.Int64() > math.MaxInt {
		d.SaveError(fmt.Errorf("jwk: parameter e out of range: %d", e))
		return
	}
	privateKey.PublicKey.E = int(e.Int64())
	n := d.MustBigInt("n")
	pub := rsa.PublicKey{
		E: int(e.Int64()),
		N: n,
	}
	key.PublicKey = &pub

	// parameters for private key
	if d.Has("d") {
		priv := rsa.PrivateKey{
			PublicKey: pub,
			D:         d.MustBigInt("d"),
			Primes: []*big.Int{
				d.MustBigInt("p"),
				d.MustBigInt("q"),
			},
		}

		// precomputed values
		crtValues := []rsa.CRTValue{}
		if oth, ok := d.GetArray("oth"); ok {
			crtValues = make([]rsa.CRTValue, 0, len(oth))
			for i, v := range oth {
				u, ok := v.(map[string]any)
				if !ok {
					d.SaveError(fmt.Errorf("jwk: want map[string]any for the parameter oth[%d] but got %T", i, v))
					return
				}
				r := parseRSAOthParam(d, i, u, "r")
				privateKey.Primes = append(privateKey.Primes, r)
				crtValues = append(crtValues, rsa.CRTValue{
					Exp:   parseRSAOthParam(d, i, u, "d"),
					Coeff: parseRSAOthParam(d, i, u, "t"),
					R:     r,
				})
			}
		}
		if d.Has("dp") && d.Has("dq") && d.Has("qi") {
			privateKey.Precomputed = rsa.PrecomputedValues{
				Dp:        d.MustBigInt("dp"),
				Dq:        d.MustBigInt("dq"),
				Qinv:      d.MustBigInt("qi"),
				CRTValues: crtValues,
			}
		}
		if err := d.Err(); err != nil {
			return
		}
		if err := priv.Validate(); err != nil {
			d.SaveError(err)
			return
		}
		priv.Precompute()
		key.PrivateKey = &priv
	}

	// sanity check of the certificate
	if certs := key.X509CertificateChain; len(certs) > 0 {
		cert := certs[0]
		if !pub.Equal(cert.PublicKey) {
			d.SaveError(errors.New("jwk: public keys are mismatch"))
		}
	}
}

func parseRSAOthParam(d *jsonutils.Decoder, i int, v map[string]any, name string) *big.Int {
	u, ok := v[name]
	if !ok {
		return nil
	}
	w, ok := u.(string)
	if !ok {
		return nil
	}
	return new(big.Int).SetBytes(d.Decode(w, fmt.Sprintf("oth[%d].%s", i, name)))
}

func encodeRSAKey(e *jsonutils.Encoder, priv *rsa.PrivateKey, pub *rsa.PublicKey) {
	e.Set("kty", jwa.RSA.String())

	if pub.E < 0 {
		e.SaveError(fmt.Errorf("jwk: parameter e out of range: %d", pub.E))
		return
	}
	var buf [8]byte
	i := 7
	for v := pub.E; v != 0; v >>= 8 {
		buf[i] = byte(v % 0x100)
		i--
	}
	e.SetBytes("e", buf[i:])
	e.SetBigInt("n", pub.N)

	if priv != nil {
		e.SetBigInt("d", priv.D)
		e.SetBigInt("p", priv.Primes[0])
		e.SetBigInt("q", priv.Primes[1])

		// precomputed values
		if priv.Precomputed.Dp != nil {
			e.SetBigInt("dp", priv.Precomputed.Dp)
			e.SetBigInt("dq", priv.Precomputed.Dq)
			e.SetBigInt("qi", priv.Precomputed.Qinv)
			oth := make([]map[string]string, 0, len(priv.Precomputed.CRTValues))
			for _, v := range priv.Precomputed.CRTValues {
				u := make(map[string]string)
				u["d"] = e.Encode(v.Exp.Bytes())
				u["t"] = e.Encode(v.Coeff.Bytes())
				u["r"] = e.Encode(v.R.Bytes())
				oth = append(oth, u)
			}
			if len(oth) > 0 {
				e.Set("oth", oth)
			}
		}
	}
}
