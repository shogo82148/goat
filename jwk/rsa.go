package jwk

import (
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/shogo82148/goat/internal/jsonutils"
)

func parseRSAKey(d *jsonutils.Decoder, key *Key) {
	var privateKey rsa.PrivateKey

	// parameters for public key
	var e int
	for _, v := range d.MustBytes("e") {
		e = (e << 8) | int(v)
	}
	privateKey.PublicKey.E = e
	privateKey.PublicKey.N = d.MustBigInt("n")
	key.PublicKey = &privateKey.PublicKey

	// parameters for private key
	if !d.Has("d") {
		return
	}
	privateKey.D = d.MustBigInt("d")
	privateKey.Primes = []*big.Int{
		d.MustBigInt("p"),
		d.MustBigInt("q"),
	}

	// precomputed values
	if oth, ok := d.GetArray("oth"); ok {
		crtValues := make([]rsa.CRTValue, 0, len(oth))
		for _, v := range oth {
			u, ok := v.(map[string]any)
			if !ok {
				d.NewError(fmt.Errorf("jwk: want string for the parameter oth[].r but got %T", v))
				return
			}
			r := parseRSAOthParam(d, u, "r")
			privateKey.Primes = append(privateKey.Primes, r)
			crtValues = append(crtValues, rsa.CRTValue{
				Exp:   parseRSAOthParam(d, u, "d"),
				Coeff: parseRSAOthParam(d, u, "t"),
				R:     r,
			})
		}

		if d.Has("dp") && d.Has("dq") && d.Has("qi") {
			privateKey.Precomputed = rsa.PrecomputedValues{
				Dp:        d.MustBigInt("dp"),
				Dq:        d.MustBigInt("dq"),
				Qinv:      d.MustBigInt("qi"),
				CRTValues: crtValues,
			}
		}
	}

	privateKey.Precompute()
	key.PrivateKey = &privateKey
}

func parseRSAOthParam(d *jsonutils.Decoder, v map[string]any, name string) *big.Int {
	u, ok := v[name]
	if !ok {
		return nil
	}
	w, ok := u.(string)
	if !ok {
		return nil
	}
	return new(big.Int).SetBytes(d.Decode(w, fmt.Sprintf("oth[].%s", name)))
}
