package jwk

import (
	"crypto/rsa"
	"math/big"
)

func parseRSAKey(data *commonKey) (*Key, error) {
	ctx := newRSAContext(data)
	key, err := data.decode(ctx)
	if err != nil {
		return nil, err
	}
	var privateKey rsa.PrivateKey

	// parameters for public key
	var e int
	for _, v := range ctx.decode(data.E, "e") {
		e = (e << 8) | int(v)
	}
	privateKey.PublicKey.E = e
	privateKey.PublicKey.N = new(big.Int).SetBytes(ctx.decode(data.N, "n"))
	key.PublicKey = &privateKey.PublicKey

	// parameters for private key
	if data.D != "" {
		d := new(big.Int).SetBytes(ctx.decode(data.D, "d"))
		p := new(big.Int).SetBytes(ctx.decode(data.P, "p"))
		q := new(big.Int).SetBytes(ctx.decode(data.Q, "q"))
		privateKey.D = d
		privateKey.Primes = []*big.Int{p, q}

		key.PrivateKey = &privateKey
	}

	if ctx.err != nil {
		return nil, ctx.err
	}
	return key, nil
}

func newRSAContext(key *commonKey) *base64Context {
	var size int
	if len(key.E) > size {
		size = len(key.E)
	}
	if len(key.N) > size {
		size = len(key.N)
	}
	if len(key.D) > size {
		size = len(key.D)
	}
	if len(key.P) > size {
		size = len(key.P)
	}
	if len(key.Q) > size {
		size = len(key.Q)
	}
	for _, v := range key.Oth {
		if len(v.R) > size {
			size = len(v.R)
		}
		if len(v.D) > size {
			size = len(v.D)
		}
		if len(v.D) > size {
			size = len(v.D)
		}
	}
	if len(key.Dp) > size {
		size = len(key.Dp)
	}
	if len(key.Dq) > size {
		size = len(key.Dq)
	}
	if len(key.Qi) > size {
		size = len(key.Qi)
	}
	if len(key.X5t) > size {
		size = len(key.X5t)
	}
	if len(key.X5tS256) > size {
		size = len(key.X5tS256)
	}
	return newBase64Context(size)
}
