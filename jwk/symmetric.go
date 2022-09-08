package jwk

func parseSymmetricKey(data *commonKey) (*Key, error) {
	ctx := newSymmetricContext(data)
	key, err := data.decode(ctx)
	if err != nil {
		return nil, err
	}

	privateKey := ctx.decode(data.K, "k")
	key.PrivateKey = privateKey

	if ctx.err != nil {
		return nil, ctx.err
	}
	return key, nil
}

func newSymmetricContext(key *commonKey) *base64Context {
	var size int
	if len(key.K) > size {
		size = len(key.K)
	}
	if len(key.X5t) > size {
		size = len(key.X5t)
	}
	if len(key.X5tS256) > size {
		size = len(key.X5tS256)
	}
	return newBase64Context(size)
}
