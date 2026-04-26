package jwk

import (
	"crypto/rsa"
	"errors"
	"math"
	"math/big"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
)

func parseRSAKey(d *jsonutils.Decoder, key *Key) {
	var privateKey rsa.PrivateKey

	// parameters for public key
	e := d.MustBigInt("e")
	if err := d.Err(); err != nil {
		return
	}
	if !e.IsInt64() || e.Int64() > math.MaxInt || e.Int64() <= 0 {
		d.SaveError(errors.New("jwk: invalid rsa parameter e"))
		return
	}
	privateKey.PublicKey.E = int(e.Int64())
	n := d.MustBigInt("n")
	pub := rsa.PublicKey{
		E: int(e.Int64()),
		N: n,
	}
	key.pub = &pub
	if err := d.Err(); err != nil {
		return
	}
	if err := validateRSAPublicKey(&pub); err != nil {
		d.SaveError(err)
		return
	}

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
		if d.Has("dp") && d.Has("dq") && d.Has("qi") {
			privateKey.Precomputed = rsa.PrecomputedValues{
				Dp:   d.MustBigInt("dp"),
				Dq:   d.MustBigInt("dq"),
				Qinv: d.MustBigInt("qi"),
			}
		}
		if err := d.Err(); err != nil {
			return
		}

		if err := validateRSAPrivateKey(&priv); err != nil {
			d.SaveError(err)
			return
		}
		priv.Precompute()
		key.priv = &priv
	}

	// sanity check of the certificate
	if certs := key.x5c; len(certs) > 0 {
		cert := certs[0]
		if !pub.Equal(cert.PublicKey) {
			d.SaveError(errors.New("jwk: public keys are mismatch"))
		}
	}
}

func encodeRSAKey(e *jsonutils.Encoder, priv *rsa.PrivateKey, pub *rsa.PublicKey) {
	e.Set("kty", jwa.KeyTypeRSA.String())

	if err := validateRSAPublicKey(pub); err != nil {
		e.SaveError(err)
		return
	}

	var buf [8]byte
	i := 8
	for v := pub.E; v != 0; v >>= 8 {
		i--
		buf[i] = byte(v % 0x100)
	}
	e.SetBytes("e", buf[i:])
	e.SetBigInt("n", pub.N)

	if priv != nil {
		if err := validateRSAPrivateKey(priv); err != nil {
			e.SaveError(err)
			return
		}
		e.SetBigInt("d", priv.D)
		e.SetBigInt("p", priv.Primes[0])
		e.SetBigInt("q", priv.Primes[1])

		// precomputed values
		if priv.Precomputed.Dp != nil {
			e.SetBigInt("dp", priv.Precomputed.Dp)
			e.SetBigInt("dq", priv.Precomputed.Dq)
			e.SetBigInt("qi", priv.Precomputed.Qinv)
		}
	}
}

// sanity check of private key
func validateRSAPrivateKey(key *rsa.PrivateKey) error {
	return key.Validate()
}

// sanity check of public key
func validateRSAPublicKey(key *rsa.PublicKey) error {
	if key.N == nil || key.N.Sign() <= 0 {
		return errors.New("jwk: invalid rsa modulus")
	}
	if key.E < 2 || key.E > math.MaxInt32 {
		return errors.New("jwk: invalid rsa public exponent")
	}
	return nil
}
