package jwk

import "math/big"

func newBigInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("failed to parse " + s)
	}
	return n
}
