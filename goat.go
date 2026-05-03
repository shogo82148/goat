// Package goat is Go Authentication Toolkit.
// It provides utils for authentication.
package goat

// PrivateKey represents a private key using an unspecified algorithm.
// It is one of [crypto.PrivateKey], [crypto.Decapsulator] or []byte.
type PrivateKey any

// PublicKey represents a public key using an unspecified algorithm.
// It is one of [crypto.PublicKey], [crypto.Encapsulator].
type PublicKey any
