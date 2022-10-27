// Copyright (c) 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards448

import (
	"crypto/subtle"
	"errors"
	"math/big"
)

var (
	scMinusOne = Scalar{
		s: [56]byte{
			0xf2, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
			0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
			0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
			0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
		},
	}
)

// A Scalar is an integer modulo
//
//	l = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
//
// which is the prime order of the edwards25519 group.
//
// This type works similarly to math/big.Int, and all arguments and
// receivers are allowed to alias.
//
// The zero value is a valid zero element.
type Scalar struct {
	v *big.Int

	// s is the Scalar value in little-endian. The value is always reduced
	// modulo l between operations.
	s [56]byte
}

func NewScalar() *Scalar {
	return &Scalar{v: new(big.Int)}
}

var l, _ = new(big.Int).SetString("181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779", 10)

func (s *Scalar) MulAdd(x, y, z *Scalar) *Scalar {
	// TODO: reimplement with constant-time algorithm
	s.v.Mul(x.v, y.v)
	s.v.Add(s.v, z.v)
	s.v.Mod(s.v, l)
	return s.fillBytes()
}

func (s *Scalar) fillBytes() *Scalar {
	var buf [56]byte
	s.v.FillBytes(buf[:])
	for i := 0; i < len(buf)/2; i++ {
		buf[i], buf[len(buf)-i-1] = buf[len(buf)-i-1], buf[i]
	}
	s.s = buf
	return s
}

func (s *Scalar) fromBytes() *Scalar {
	buf := s.s
	for i := 0; i < len(buf)/2; i++ {
		buf[i], buf[len(buf)-i-1] = buf[len(buf)-i-1], buf[i]
	}
	s.v.SetBytes(buf[:])
	return s
}

func (s *Scalar) Add(x, y *Scalar) *Scalar {
	// TODO: reimplement with constant-time algorithm
	s.v.Add(x.v, y.v)
	s.v.Mod(s.v, l)
	return s.fillBytes()
}

func (s *Scalar) Sub(x, y *Scalar) *Scalar {
	// TODO: reimplement with constant-time algorithm
	s.v.Add(x.v, l)
	s.v.Sub(s.v, y.v)
	s.v.Mod(s.v, l)
	return s.fillBytes()
}

func (s *Scalar) Negate(x *Scalar) *Scalar {
	// TODO: reimplement with constant-time algorithm
	s.v.Sub(l, x.v)
	s.v.Mod(s.v, l)
	return s.fillBytes()
}

func (s *Scalar) Mul(x, y *Scalar) *Scalar {
	// TODO: reimplement with constant-time algorithm
	s.v.Mul(x.v, y.v)
	s.v.Mod(s.v, l)
	return s.fillBytes()
}

func (s *Scalar) Set(x *Scalar) *Scalar {
	s.v.Set(x.v)
	s.v.Mod(s.v, l)
	s.s = x.s
	return s
}

// Equal returns 1 if s and t are equal, and 0 otherwise.
func (s *Scalar) Equal(t *Scalar) int {
	return subtle.ConstantTimeCompare(s.s[:], t.s[:])
}

// SetUniformBytes sets s = x mod l, where x is a 114-byte little-endian integer.
// If x is not of the right length, SetUniformBytes returns nil and an error,
// and the receiver is unchanged.
//
// SetUniformBytes can be used to set s to an uniformly distributed value given
// 64 uniformly distributed random bytes.
func (s *Scalar) SetUniformBytes(x []byte) (*Scalar, error) {
	if len(x) != 114 {
		return nil, errors.New("edwards448: invalid SetUniformBytes input length")
	}

	// TODO: reimplement with constant-time algorithm
	var buf [114]byte
	copy(buf[:], x)
	for i := 0; i < len(buf)/2; i++ {
		buf[i], buf[len(buf)-i-1] = buf[len(buf)-i-1], buf[i]
	}
	s.v.SetBytes(buf[:])
	s.v.Mod(s.v, l)
	return s.fillBytes(), nil
}

// SetCanonicalBytes sets s = x, where x is a 57-byte little-endian encoding of
// s, and returns s. If x is not a canonical encoding of s, SetCanonicalBytes
// returns nil and an error, and the receiver is unchanged.
func (s *Scalar) SetCanonicalBytes(x []byte) (*Scalar, error) {
	if len(x) != 57 {
		return nil, errors.New("edwards448: invalid SetBytesWithClamping input length")
	}

	var ss Scalar
	copy(ss.s[:], x)
	if x[56] != 0 || !isReduced(&ss) {
		return nil, errors.New("edwards448: invalid scalar encoding")
	}
	s.s = ss.s
	return s.fromBytes(), nil
}

func isReduced(s *Scalar) bool {
	for i := len(s.s) - 1; i >= 0; i-- {
		switch {
		case s.s[i] > scMinusOne.s[i]:
			return false
		case s.s[i] < scMinusOne.s[i]:
			return true
		}
	}
	return true
}

// SetBytesWithClamping applies the buffer pruning described in RFC 8032,
// Section 5.2.5 (also known as clamping) and sets s to the result. The input
// must be 57 bytes, and it is not modified. If x is not of the right length,
// SetBytesWithClamping returns nil and an error, and the receiver is unchanged.
func (s *Scalar) SetBytesWithClamping(x []byte) (*Scalar, error) {
	if len(x) != 57 {
		return nil, errors.New("edwards448: invalid SetBytesWithClamping input length")
	}

	copy(s.s[:], x)
	s.s[0] &^= 0x03
	s.s[55] |= 0x80
	return s.fromBytes(), nil
}

func (s *Scalar) Bytes() [56]byte {
	return s.s
}
