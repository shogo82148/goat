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

	var wide [114]byte
	copy(wide[:], x)
	scReduce(&s.s, &wide)
	return s.fromBytes(), nil
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

	var wide [114]byte
	copy(wide[:], x)
	wide[0] &^= 0x03
	wide[55] |= 0x80
	wide[56] = 0
	scReduce(&s.s, &wide)
	return s.fromBytes(), nil
}

func (s *Scalar) Bytes() [56]byte {
	return s.s
}

// Input:
//
//	s[0]+256*s[1]+...+256^113*s[113] = s
//
// Output:
//
//	s[0]+256*s[1]+...+256^31*s[56] = s mod l
//	where l = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885.
func scReduce(out *[56]byte, s *[114]byte) {
	// [print("s%d := int64(s[%d]) | int64(s[%d])<<8 | int64(s[%d])<<16" % (i, i*3, i*3+1, i*3+2)) for i in range(38)]
	s0 := int64(s[0]) | int64(s[1])<<8 | int64(s[2])<<16
	s1 := int64(s[3]) | int64(s[4])<<8 | int64(s[5])<<16
	s2 := int64(s[6]) | int64(s[7])<<8 | int64(s[8])<<16
	s3 := int64(s[9]) | int64(s[10])<<8 | int64(s[11])<<16
	s4 := int64(s[12]) | int64(s[13])<<8 | int64(s[14])<<16
	s5 := int64(s[15]) | int64(s[16])<<8 | int64(s[17])<<16
	s6 := int64(s[18]) | int64(s[19])<<8 | int64(s[20])<<16
	s7 := int64(s[21]) | int64(s[22])<<8 | int64(s[23])<<16
	s8 := int64(s[24]) | int64(s[25])<<8 | int64(s[26])<<16
	s9 := int64(s[27]) | int64(s[28])<<8 | int64(s[29])<<16
	s10 := int64(s[30]) | int64(s[31])<<8 | int64(s[32])<<16
	s11 := int64(s[33]) | int64(s[34])<<8 | int64(s[35])<<16
	s12 := int64(s[36]) | int64(s[37])<<8 | int64(s[38])<<16
	s13 := int64(s[39]) | int64(s[40])<<8 | int64(s[41])<<16
	s14 := int64(s[42]) | int64(s[43])<<8 | int64(s[44])<<16
	s15 := int64(s[45]) | int64(s[46])<<8 | int64(s[47])<<16
	s16 := int64(s[48]) | int64(s[49])<<8 | int64(s[50])<<16
	s17 := int64(s[51]) | int64(s[52])<<8 | int64(s[53])<<16
	s18 := int64(s[54]) | int64(s[55])<<8 | int64(s[56])<<16
	s19 := int64(s[57]) | int64(s[58])<<8 | int64(s[59])<<16
	s20 := int64(s[60]) | int64(s[61])<<8 | int64(s[62])<<16
	s21 := int64(s[63]) | int64(s[64])<<8 | int64(s[65])<<16
	s22 := int64(s[66]) | int64(s[67])<<8 | int64(s[68])<<16
	s23 := int64(s[69]) | int64(s[70])<<8 | int64(s[71])<<16
	s24 := int64(s[72]) | int64(s[73])<<8 | int64(s[74])<<16
	s25 := int64(s[75]) | int64(s[76])<<8 | int64(s[77])<<16
	s26 := int64(s[78]) | int64(s[79])<<8 | int64(s[80])<<16
	s27 := int64(s[81]) | int64(s[82])<<8 | int64(s[83])<<16
	s28 := int64(s[84]) | int64(s[85])<<8 | int64(s[86])<<16
	s29 := int64(s[87]) | int64(s[88])<<8 | int64(s[89])<<16
	s30 := int64(s[90]) | int64(s[91])<<8 | int64(s[92])<<16
	s31 := int64(s[93]) | int64(s[94])<<8 | int64(s[95])<<16
	s32 := int64(s[96]) | int64(s[97])<<8 | int64(s[98])<<16
	s33 := int64(s[99]) | int64(s[100])<<8 | int64(s[101])<<16
	s34 := int64(s[102]) | int64(s[103])<<8 | int64(s[104])<<16
	s35 := int64(s[105]) | int64(s[106])<<8 | int64(s[107])<<16
	s36 := int64(s[108]) | int64(s[109])<<8 | int64(s[110])<<16
	s37 := int64(s[111]) | int64(s[112])<<8 | int64(s[113])<<16

	s0 += s19 * 0xec3400
	s1 += s19 * 0xb5529e
	s2 += s19 * 0x721cf5
	s3 += s19 * 0xe9c2ab
	s4 += s19 * 0xf635c8
	s5 += s19 * 0xbf7a4c
	s6 += s19 * 0x44a725
	s7 += s19 * 0xc492d9
	s8 += s19 * 0x7058ee
	s9 += s19 * 0x020cd7

	_ = s20
	_ = s21
	_ = s22
	_ = s23
	_ = s24
	_ = s25
	_ = s26
	_ = s27
	_ = s28
	_ = s29
	_ = s30
	_ = s31
	_ = s32
	_ = s33
	_ = s34
	_ = s35
	_ = s36
	_ = s37

	c := s18 >> 14
	s0 += c * 0xa7bb0d
	s1 += c * 0x3d6d54
	s2 += c * 0xaadc87
	s3 += c * 0x723a70
	s4 += c * 0x933d8d
	s5 += c * 0xc96fde
	s6 += c * 0xb65129
	s7 += c * 0x3bb124
	s8 += c * 0x35dc16
	s9 += c * 0x000083
	s18 &= 0x003FFF

	d := (s0 + 0xa7bb0d) >> 24
	d = (s1 + 0x3d6d54 + d) >> 24
	d = (s2 + 0xaadc87 + d) >> 24
	d = (s3 + 0x723a70 + d) >> 24
	d = (s4 + 0x933d8d + d) >> 24
	d = (s5 + 0xc96fde + d) >> 24
	d = (s6 + 0xb65129 + d) >> 24
	d = (s7 + 0x3bb124 + d) >> 24
	d = (s8 + 0x35dc16 + d) >> 24
	d = (s9 + 0x000083 + d) >> 24
	d = (s10 + d) >> 24
	d = (s11 + d) >> 24
	d = (s12 + d) >> 24
	d = (s13 + d) >> 24
	d = (s14 + d) >> 24
	d = (s15 + d) >> 24
	d = (s16 + d) >> 24
	d = (s17 + d) >> 24
	d = (s18 + d) >> 14

	// If s < l and d = 0, this will be a no-op. Otherwise, it's
	// effectively applying the reduction identity to the carry.
	s0 += d * 0xa7bb0d
	c = s0 >> 24
	s0 -= c << 24
	s1 += d*0x3d6d54 + c
	c = s1 >> 24
	s1 -= c << 24
	s2 += d*0xaadc87 + c
	c = s2 >> 24
	s2 -= c << 24
	s3 += d*0x723a70 + c
	c = s3 >> 24
	s3 -= c << 24
	s4 += d*0x933d8d + c
	c = s4 >> 24
	s4 -= c << 24
	s5 += d*0xc96fde + c
	c = s5 >> 24
	s5 -= c << 24
	s6 += d*0xb65129 + c
	c = s6 >> 24
	s6 -= c << 24
	s7 += d*0x3bb124 + c
	c = s7 >> 24
	s7 -= c << 24
	s8 += d*0x35dc16 + c
	c = s8 >> 24
	s8 -= c << 24
	s9 += d*0x000083 + c
	c = s9 >> 24
	s9 -= c << 24
	s10 += c
	c = s10 >> 24
	s10 -= c << 24
	s11 += c
	c = s11 >> 24
	s11 -= c << 24
	s12 += c
	c = s12 >> 24
	s12 -= c << 24
	s13 += c
	c = s13 >> 24
	s13 -= c << 24
	s14 += c
	c = s14 >> 24
	s14 -= c << 24
	s15 += c
	c = s15 >> 24
	s15 -= c << 24
	s16 += c
	c = s16 >> 24
	s16 -= c << 24
	s17 += c
	c = s17 >> 24
	s17 -= c << 24
	s18 += c
	c = s18 >> 14
	s18 -= c << 14
	// no additional carry

	// [print("out[%d] = byte(s%d >> %d)" % (i, i//3, (i%3)*8)) for i in range(56)]
	out[0] = byte(s0 >> 0)
	out[1] = byte(s0 >> 8)
	out[2] = byte(s0 >> 16)
	out[3] = byte(s1 >> 0)
	out[4] = byte(s1 >> 8)
	out[5] = byte(s1 >> 16)
	out[6] = byte(s2 >> 0)
	out[7] = byte(s2 >> 8)
	out[8] = byte(s2 >> 16)
	out[9] = byte(s3 >> 0)
	out[10] = byte(s3 >> 8)
	out[11] = byte(s3 >> 16)
	out[12] = byte(s4 >> 0)
	out[13] = byte(s4 >> 8)
	out[14] = byte(s4 >> 16)
	out[15] = byte(s5 >> 0)
	out[16] = byte(s5 >> 8)
	out[17] = byte(s5 >> 16)
	out[18] = byte(s6 >> 0)
	out[19] = byte(s6 >> 8)
	out[20] = byte(s6 >> 16)
	out[21] = byte(s7 >> 0)
	out[22] = byte(s7 >> 8)
	out[23] = byte(s7 >> 16)
	out[24] = byte(s8 >> 0)
	out[25] = byte(s8 >> 8)
	out[26] = byte(s8 >> 16)
	out[27] = byte(s9 >> 0)
	out[28] = byte(s9 >> 8)
	out[29] = byte(s9 >> 16)
	out[30] = byte(s10 >> 0)
	out[31] = byte(s10 >> 8)
	out[32] = byte(s10 >> 16)
	out[33] = byte(s11 >> 0)
	out[34] = byte(s11 >> 8)
	out[35] = byte(s11 >> 16)
	out[36] = byte(s12 >> 0)
	out[37] = byte(s12 >> 8)
	out[38] = byte(s12 >> 16)
	out[39] = byte(s13 >> 0)
	out[40] = byte(s13 >> 8)
	out[41] = byte(s13 >> 16)
	out[42] = byte(s14 >> 0)
	out[43] = byte(s14 >> 8)
	out[44] = byte(s14 >> 16)
	out[45] = byte(s15 >> 0)
	out[46] = byte(s15 >> 8)
	out[47] = byte(s15 >> 16)
	out[48] = byte(s16 >> 0)
	out[49] = byte(s16 >> 8)
	out[50] = byte(s16 >> 16)
	out[51] = byte(s17 >> 0)
	out[52] = byte(s17 >> 8)
	out[53] = byte(s17 >> 16)
	out[54] = byte(s18 >> 0)
	out[55] = byte(s18 >> 8)
}
