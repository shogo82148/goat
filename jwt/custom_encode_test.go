package jwt

import (
	"encoding/json"
	"math/big"
	"net/url"
	"reflect"
	"testing"
	"time"
)

func TestEncodeCustom(t *testing.T) {
	type MyClaims struct {
		String    string  `jwt:"string"`
		Int       int     `jwt:"int"`
		Int8      int8    `jwt:"int8"`
		Int16     int16   `jwt:"int16"`
		Int32     int32   `jwt:"int32"`
		Int64     int64   `jwt:"int64"`
		Uint      int     `jwt:"uint"`
		Uint8     int8    `jwt:"uint8"`
		Uint16    int16   `jwt:"uint16"`
		Uint32    int32   `jwt:"uint32"`
		Uint64    int64   `jwt:"uint64"`
		Float32   float32 `jwt:"float32"`
		Float64   float64 `jwt:"float64"`
		True      bool    `jwt:"true"`
		False     bool    `jwt:"false"`
		NotTagged string
		private   string
	}

	type Embed0 struct {
		Foo string `jwt:"foo"`
	}
	type Embed0a struct {
		Foo1a string `jwt:"foo1a"`
	}
	type Parent struct {
		Embed0
		*Embed0a
		Bar string `jwt:"bar"`
	}

	cases := []struct {
		in   any
		want map[string]any
	}{
		{
			in: &MyClaims{
				String:    "foobar",
				Int:       1,
				Int8:      8,
				Int16:     16,
				Int32:     32,
				Int64:     64,
				Uint:      1,
				Uint8:     8,
				Uint16:    16,
				Uint32:    32,
				Uint64:    64,
				Float32:   0.5,
				Float64:   0.5,
				True:      true,
				False:     false,
				NotTagged: "NotTagged",
				private:   "private",
			},
			want: map[string]any{
				"string":  "foobar",
				"int":     json.Number("1"),
				"int8":    json.Number("8"),
				"int16":   json.Number("16"),
				"int32":   json.Number("32"),
				"int64":   json.Number("64"),
				"uint":    json.Number("1"),
				"uint8":   json.Number("8"),
				"uint16":  json.Number("16"),
				"uint32":  json.Number("32"),
				"uint64":  json.Number("64"),
				"float32": json.Number("0.5"),
				"float64": json.Number("0.5"),
				"true":    true,
				"false":   false,
			},
		},
		{
			in: &Parent{
				Embed0: Embed0{
					Foo: "foo",
				},
				Embed0a: &Embed0a{
					Foo1a: "foo1a",
				},
				Bar: "bar",
			},
			want: map[string]any{
				"foo":   "foo",
				"foo1a": "foo1a",
				"bar":   "bar",
			},
		},

		// byte sequence
		{
			in: &struct {
				Bytes []byte `jwt:"bytes"`
			}{
				Bytes: []byte(`{"iss":"joe",` + "\r\n" +
					` "exp":1300819380,` + "\r\n" +
					` "http://example.com/is_root":true}`),
			},
			want: map[string]any{
				"bytes": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
					"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
			},
		},

		// time
		{
			in: &struct {
				Time time.Time `jwt:"time"`
			}{
				Time: time.Unix(1300819380, 0),
			},
			want: map[string]any{
				"time": json.Number("1300819380"),
			},
		},

		// url
		{
			in: &struct {
				URL *url.URL `jwt:"url"`
			}{
				URL: &url.URL{
					Scheme: "http",
					Host:   "example.com",
					Path:   "/is_root",
				},
			},
			want: map[string]any{
				"url": "http://example.com/is_root",
			},
		},

		// big.Int
		{
			in: &struct {
				X *big.Int `jwt:"x"`
			}{
				X: new(big.Int).SetBytes([]byte{
					0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
					0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
				}),
			},
			want: map[string]any{
				"x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
		},
	}
	for i, tc := range cases {
		claims := &Claims{}
		if err := claims.EncodeCustom(tc.in); err != nil {
			t.Errorf("%d: error: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(claims.Raw, tc.want) {
			t.Errorf("%d: want %#v, got %#v", i, tc.want, claims.Raw)
		}
	}
}
