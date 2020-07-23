package selfupdate

import (
	"io/ioutil"
	"testing"
)

func TestMinisign(t *testing.T) {
	v := NewVerifier()
	if err := v.LoadFromFile("test.minisig", "RWTx5Zr1tiHQLwG9keckT0c45M3AGeHD6IvimQHpyRywVWGbP1aVSGav"); err != nil {
		t.Fatal(err)
	}

	buf, err := ioutil.ReadFile("LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Verify(buf); err != nil {
		t.Fatal(err)
	}
}
