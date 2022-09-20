package jsonutils

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNumericDate_MarshalJSON(t *testing.T) {
	testCases := []struct {
		output string
		date   time.Time
	}{
		{
			output: "-1",
			date:   time.Unix(-1, 0),
		},
		{
			output: "0",
			date:   time.Unix(0, 0),
		},
		{
			output: "1234567890",
			date:   time.Unix(1234567890, 0),
		},
		{
			output: "1234567890.123456789",
			date:   time.Unix(1234567890, 123_456_789),
		},
		{
			output: "1234567890.123456",
			date:   time.Unix(1234567890, 123_456_000),
		},
		{
			output: "1234567890.1",
			date:   time.Unix(1234567890, 100_000_000),
		},
		{
			// the maximum time.Time that Go can marshal to JSON.
			output: "253402300799.999999999",
			date:   time.Date(9999, time.December, 31, 23, 59, 59, 999_999_999, time.UTC),
		},
	}

	for _, tc := range testCases {
		got, err := json.Marshal(NumericDate{tc.date})
		if err != nil {
			t.Errorf("failed to marshal %s", tc.date)
			continue
		}
		if string(got) != tc.output {
			t.Errorf("marshal %s not match: want %s, got %s", tc.date, tc.output, string(got))
		}
	}
}

func BenchmarkNumericDate_MarshalJSON(b *testing.B) {
	date := NumericDate{
		time.Date(9999, time.December, 31, 23, 59, 59, 999_999_999, time.UTC),
	}
	for i := 0; i < b.N; i++ {
		if _, err := date.MarshalJSON(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestNumericDate_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		input string
		date  time.Time
	}{
		{
			input: "-1",
			date:  time.Unix(-1, 0),
		},
		{
			input: "0",
			date:  time.Unix(0, 0),
		},
		{
			input: "1234567890",
			date:  time.Unix(1234567890, 0),
		},
		{
			input: "1234567890.123456789",
			date:  time.Unix(1234567890, 123456789),
		},
		{
			// Time shorter than one nanosecond is truncated.
			input: "1234567890.9999999999",
			date:  time.Unix(1234567890, 999999999),
		},
		{
			// the maximum time.Time that Go can marshal to JSON.
			input: "253402300799.999999999",
			date:  time.Date(9999, time.December, 31, 23, 59, 59, 999_999_999, time.UTC),
		},
	}

	for _, tc := range testCases {
		var got NumericDate
		if err := json.Unmarshal([]byte(tc.input), &got); err != nil {
			t.Errorf("failed parse %q: %v", tc.input, err)
		}
		if !got.Equal(tc.date) {
			t.Errorf("the result of %q is unexpected: want %s, got %s", tc.input, tc.date, got)
		}
	}
}

func BenchmarkNumericDate_UnmarshalJSON(b *testing.B) {
	input := []byte("253402300799.999999999")
	for i := 0; i < b.N; i++ {
		var date NumericDate
		if err := date.UnmarshalJSON(input); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzNumericDate(f *testing.F) {
	f.Add("1234567890")
	f.Add("1234567890.123456789")
	f.Add("1234567890.123456")
	f.Add("1234567890.1")
	f.Add("253402300799.999999999")
	f.Add("9223371974719179007.999999999")

	f.Fuzz(func(t *testing.T, s string) {
		var t1, t2 NumericDate
		if err := t1.UnmarshalJSON([]byte(s)); err != nil {
			// s is not a numeric date.
			return
		}

		// Marshal and Unmarshal
		data, err := t1.MarshalJSON()
		if err != nil {
			t.Errorf("failed to marshal: %v", err)
		}
		if err := t2.UnmarshalJSON(data); err != nil {
			t.Errorf("failed to unmarshal: %v", err)
		}

		if !t1.Equal(t2.Time) {
			t.Errorf("unexpected date time parsing %q: want %v got %v", string(data), t1, t2)
		}
	})
}
