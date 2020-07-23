package selfupdate

import (
	"io/ioutil"
	"testing"
)

func TestMinisign(t *testing.T) {
	v := NewVerifier()
	if err := v.LoadFromFile("test.pub", "test.minisig"); err != nil {
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
