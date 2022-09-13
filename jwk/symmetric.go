package jwk

func parseSymmetricKey(ctx *decodeContext, key *Key) {
	privateKey := ctx.mustBytes("k")
	key.PrivateKey = privateKey
}
