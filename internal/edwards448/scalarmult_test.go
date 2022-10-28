package edwards448

import "testing"

func TestScalarBaseMult(t *testing.T) {
	t.Run("positive", func(t *testing.T) {
		s := new(Scalar)
		g := NewGeneratorPoint()
		want := new(Point).Zero()
		for i := 0; i < 1024; i++ {
			got := new(Point).ScalarBaseMult(s)
			if got.Equal(want) == 0 {
				t.Errorf("got %#v, want %#v", got, want)
			}
			s.Add(s, &scOne)
			want.Add(want, g)
		}
	})

	t.Run("negative", func(t *testing.T) {
		s := new(Scalar)
		g := NewGeneratorPoint()
		g.Negate(g)
		want := new(Point).Zero()
		for i := 0; i < 1024; i++ {
			got := new(Point).ScalarBaseMult(s)
			if got.Equal(want) == 0 {
				t.Errorf("got %#v, want %#v", got, want)
			}
			s.Add(s, &scMinusOne)
			want.Add(want, g)
		}
	})
}
