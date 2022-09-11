package jwk

import (
	"errors"
	"fmt"

	"github.com/shogo82148/goat/jwa"
)

// RFC8037 2.  Key Type "OKP"
func parseOKPKey(data *commonKey) (*Key, error) {
	ctx := newOKPContext(data)
	key, err := data.decode(ctx)
	if err != nil {
		return nil, err
	}
	switch data.Crv {
	case jwa.Ed25519:
		return parseEd25519Key(ctx, data, key)
	case "":
		return nil, errors.New("jwk: the crv parameter is missing")
	default:
		return nil, fmt.Errorf("jwk: unknown crv: %q", data.Crv)
	}
}

func newOKPContext(key *commonKey) *base64Context {
	var size int
	if len(key.X) > size {
		size = len(key.X)
	}
	if len(key.D) > size {
		size = len(key.D)
	}
	if len(key.X5t) > size {
		size = len(key.X5t)
	}
	if len(key.X5tS256) > size {
		size = len(key.X5tS256)
	}
	return newBase64Context(size)
}
