// Copyright (c) 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards448

import (
	"errors"
	"math/big"
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
}

func NewScalar() *Scalar {
	return &Scalar{new(big.Int)}
}

var l, _ = new(big.Int).SetString("181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779", 10)

func (s *Scalar) MulAdd(x, y, z *Scalar) *Scalar {
	// TODO: reimplement with constant-time algorithm
	s.v.Mul(x.v, y.v)
	s.v.Add(s.v, z.v)
	s.v.Mod(s.v, l)
	return s
}

func (s *Scalar) Add(x, y *Scalar) *Scalar {
	// TODO: reimplement with constant-time algorithm
	s.v.Add(x.v, y.v)
	s.v.Mod(s.v, l)
	return s
}

func (s *Scalar) Sub(x, y *Scalar) *Scalar {
	// TODO: reimplement with constant-time algorithm
	s.v.Add(x.v, l)
	s.v.Sub(s.v, y.v)
	s.v.Mod(s.v, l)
	return s
}

func (s *Scalar) Negate(x *Scalar) *Scalar {
	// TODO: reimplement with constant-time algorithm
	s.v.Sub(l, x.v)
	s.v.Mod(s.v, l)
	return s
}

func (s *Scalar) Mul(x, y *Scalar) *Scalar {
	// TODO: reimplement with constant-time algorithm
	s.v.Mul(x.v, y.v)
	s.v.Mod(s.v, l)
	return s
}

func (s *Scalar) Set(x *Scalar) *Scalar {
	s.v.Set(x.v)
	s.v.Mod(s.v, l)
	return s
}

func (s *Scalar) Equal(t *Scalar) int {
	// TODO: reimplement with constant-time algorithm
	if s.v.Cmp(t.v) == 0 {
		return 1
	}
	return 0
}

func (s *Scalar) SetUniformBytes(x []byte) (*Scalar, error) {
	if len(x) != 114 {
		return nil, errors.New("edwards448: invalid SetUniformBytes input length")
	}
	var buf [114]byte
	copy(buf[:], x)
	for i := 0; i < len(buf)/2; i++ {
		buf[i], buf[len(buf)-i-1] = buf[len(buf)-i-1], buf[i]
	}
	s.v.SetBytes(buf[:])
	s.v.Mod(s.v, l)
	return s, nil
}

func (s *Scalar) SetBytesWithClamping(x []byte) (*Scalar, error) {
	if len(x) != 57 {
		return nil, errors.New("edwards448: invalid SetBytesWithClamping input length")
	}
	var buf [56]byte
	copy(buf[:], x)
	buf[0] &= 252
	buf[55] |= 128
	for i := 0; i < len(buf)/2; i++ {
		buf[i], buf[len(buf)-i-1] = buf[len(buf)-i-1], buf[i]
	}
	s.v.SetBytes(buf[:])
	s.v.Mod(s.v, l)
	return s, nil
}

func (s *Scalar) Bytes() [56]byte {
	var buf [56]byte
	s.v.FillBytes(buf[:])
	for i := 0; i < len(buf)/2; i++ {
		buf[i], buf[len(buf)-i-1] = buf[len(buf)-i-1], buf[i]
	}
	return buf
}
