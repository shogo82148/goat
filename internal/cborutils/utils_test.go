package cborutils

import "testing"

func TestIntegerFromInt64(t *testing.T) {
	tests := []int64{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		-1, -2, -3, -4, -5, -6, -7, -8, -9,
	}
	for _, test := range tests {
		i := IntegerFromInt64(test)
		j, err := i.Int64()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if j != test {
			t.Errorf("unexpected value: %d", j)
		}
	}
}
