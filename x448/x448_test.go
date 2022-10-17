package x448

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func newBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestX448_1(t *testing.T) {
	// RFC 7748 Section 5.2. Test Vectors

	k := newBytes(
		"3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121" +
			"700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
	)

	u := newBytes(
		"06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9" +
			"814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
	)

	got, err := X448(k, u)
	if err != nil {
		t.Fatal(err)
	}
	want := newBytes(
		"ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f" +
			"e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
	)
	if !bytes.Equal(want, got) {
		t.Errorf("want %x, got %x", want, got)
	}
}

func TestX448_2(t *testing.T) {
	// RFC 7748 Section 5.2. Test Vectors

	k := newBytes(
		"203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5" +
			"38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
	)

	u := newBytes(
		"0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b" +
			"165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
	)

	got, err := X448(k, u)
	if err != nil {
		t.Fatal(err)
	}
	want := newBytes(
		"884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7" +
			"ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d",
	)
	if !bytes.Equal(want, got) {
		t.Errorf("want %x, got %x", want, got)
	}
}

func TestLoop1(t *testing.T) {
	// RFC 7748 Section 5.2. Test Vectors
	// After one iteration
	k := newBytes(
		"05000000000000000000000000000000000000000000000000000000" +
			"00000000000000000000000000000000000000000000000000000000",
	)

	u := newBytes(
		"05000000000000000000000000000000000000000000000000000000" +
			"00000000000000000000000000000000000000000000000000000000",
	)

	for i := 0; i < 1; i++ {
		tmp, err := X448(k, u)
		if err != nil {
			t.Fatal(err)
		}
		k, u = tmp, k
	}
	got := hex.EncodeToString(k)
	want := "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a" +
		"4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestLoop1000(t *testing.T) {
	// RFC 7748 Section 5.2. Test Vectors
	// After 1,000 iteration
	k := newBytes(
		"05000000000000000000000000000000000000000000000000000000" +
			"00000000000000000000000000000000000000000000000000000000",
	)

	u := newBytes(
		"05000000000000000000000000000000000000000000000000000000" +
			"00000000000000000000000000000000000000000000000000000000",
	)

	for i := 0; i < 1000; i++ {
		tmp, err := X448(k, u)
		if err != nil {
			t.Fatal(err)
		}
		k, u = tmp, k
	}
	got := hex.EncodeToString(k)
	want := "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4" +
		"af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}
