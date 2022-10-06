package dir

import "testing"

func TestWrapKey(t *testing.T) {
	alg := New()
	kw := alg.NewKeyWrapper([]byte("foo bar"), nil)
	data, err := kw.WrapKey([]byte{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Errorf("invalid data: %#v", data)
	}
}

func TestUnwrapKey(t *testing.T) {
	alg := New()
	kw := alg.NewKeyWrapper([]byte("foo bar"), nil)
	data, err := kw.UnwrapKey([]byte{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "foo bar" {
		t.Errorf("invalid data: %#v", data)
	}
}
