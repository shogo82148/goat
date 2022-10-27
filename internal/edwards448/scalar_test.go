package edwards448

import (
	"encoding/hex"
	"testing"
)

func (s *Scalar) String() string {
	return hex.EncodeToString(s.s[:])
}

func TestSetUniformBytes(t *testing.T) {
	t.Run("l-1", func(t *testing.T) {
		s := NewScalar()
		_, err := s.SetUniformBytes([]byte{
			0xf2, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
			0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
			0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
			0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
			0x00,

			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00,
		})
		if err != nil {
			t.Fatal(err)
		}
		v := &Scalar{
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
		if s.Equal(v) == 0 {
			t.Errorf("got %s, want %s", s, v)
		}
	})

	t.Run("l", func(t *testing.T) {
		s := NewScalar()
		_, err := s.SetUniformBytes([]byte{
			0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
			0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
			0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
			0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
			0x00,

			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00,
		})
		if err != nil {
			t.Fatal(err)
		}
		v := &Scalar{
			s: [56]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		}
		if s.Equal(v) == 0 {
			t.Errorf("got %s, want %s", s, v)
		}
	})

	t.Run("2^446", func(t *testing.T) {
		s := NewScalar()
		_, err := s.SetUniformBytes([]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
			0x00,

			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00,
		})
		if err != nil {
			t.Fatal(err)
		}
		v := &Scalar{
			s: [56]byte{
				0x0d, 0xbb, 0xa7, 0x54, 0x6d, 0x3d, 0x87, 0xdc,
				0xaa, 0x70, 0x3a, 0x72, 0x8d, 0x3d, 0x93, 0xde,
				0x6f, 0xc9, 0x29, 0x51, 0xb6, 0x24, 0xb1, 0x3b,
				0x16, 0xdc, 0x35, 0x83, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		}
		if s.Equal(v) == 0 {
			t.Errorf("got %s, want %s", s, v)
		}
	})
}

func TestSetCanonicalBytes(t *testing.T) {
	t.Run("valid input", func(t *testing.T) {
		s := NewScalar()
		_, err := s.SetCanonicalBytes([]byte{
			0xf2, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
			0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
			0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
			0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
			0x00,
		})
		if err != nil {
			t.Fatal(err)
		}
		if s.Equal(NewScalar()) == 1 {
			t.Fatal("s should not be zero, but it is")
		}
	})

	t.Run("not reduced", func(t *testing.T) {
		s := NewScalar()
		_, err := s.SetCanonicalBytes([]byte{
			0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
			0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
			0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
			0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
			0x00,
		})
		if err == nil {
			t.Fatal(err)
		}
		if s.Equal(NewScalar()) == 0 {
			t.Fatal("s should be zero, but it is not")
		}
	})

	t.Run("invalid Most Significant Bit", func(t *testing.T) {
		s := NewScalar()
		_, err := s.SetCanonicalBytes([]byte{
			0xf2, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
			0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
			0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
			0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
			0x80,
		})
		if err == nil {
			t.Fatal(err)
		}
		if s.Equal(NewScalar()) == 0 {
			t.Fatal("s should be zero, but it is not")
		}
	})

	t.Run("short long", func(t *testing.T) {
		s := NewScalar()
		_, err := s.SetCanonicalBytes([]byte{
			0xf2, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
			0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
			0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
			0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
		})
		if err == nil {
			t.Fatal(err)
		}
		if s.Equal(NewScalar()) == 0 {
			t.Fatal("s should be zero, but it is not")
		}
	})
}