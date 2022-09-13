package jwk

import (
	"crypto/rsa"
	"fmt"
	"math/big"
)

func parseRSAKey(ctx *decodeContext, key *Key) {
	var privateKey rsa.PrivateKey

	// parameters for public key
	var e int
	for _, v := range ctx.mustBytes("e") {
		e = (e << 8) | int(v)
	}
	privateKey.PublicKey.E = e
	privateKey.PublicKey.N = new(big.Int).SetBytes(ctx.mustBytes("n"))
	key.PublicKey = &privateKey.PublicKey

	// parameters for private key
	if !ctx.has("d") {
		return
	}
	d := new(big.Int).SetBytes(ctx.mustBytes("d"))
	p := new(big.Int).SetBytes(ctx.mustBytes("p"))
	q := new(big.Int).SetBytes(ctx.mustBytes("q"))
	privateKey.D = d
	privateKey.Primes = []*big.Int{p, q}

	// precomputed values
	if oth, ok := get[[]any](ctx, "oth"); ok {
		crtValues := make([]rsa.CRTValue, 0, len(oth))
		for _, v := range oth {
			u, ok := v.(map[string]any)
			if !ok {
				ctx.error(fmt.Errorf("jwk: unexpected type for the parameter oth[].r: %T", v))
				return
			}
			r := parseRSAOthParam(ctx, u, "r")
			privateKey.Primes = append(privateKey.Primes, r)

			d := parseRSAOthParam(ctx, u, "d")
			t := parseRSAOthParam(ctx, u, "t")

			crtValues = append(crtValues, rsa.CRTValue{
				Exp:   d,
				Coeff: t,
				R:     r,
			})
		}

		if ctx.has("dp") && ctx.has("dq") && ctx.has("qi") {
			dp := new(big.Int).SetBytes(ctx.mustBytes("dp"))
			dq := new(big.Int).SetBytes(ctx.mustBytes("dq"))
			qi := new(big.Int).SetBytes(ctx.mustBytes("qi"))

			privateKey.Precomputed = rsa.PrecomputedValues{
				Dp:        dp,
				Dq:        dq,
				Qinv:      qi,
				CRTValues: crtValues,
			}
		}
	}

	privateKey.Precompute()
	key.PrivateKey = &privateKey
}

func parseRSAOthParam(ctx *decodeContext, v map[string]any, name string) *big.Int {
	u, ok := v[name]
	if !ok {
		return nil
	}
	w, ok := u.(string)
	if !ok {
		return nil
	}
	return new(big.Int).SetBytes(ctx.decode(w, fmt.Sprintf("oth[].%s", name)))
}
