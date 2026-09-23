package eax

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"errors"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// CMAC is pinned first and on its own, against the vectors of NIST SP
// 800-38B appendix D. Everything EAX does rests on it, so a fault here
// would show up as a wrong tag with no way to tell where from.
func TestCMACAgainstTheNISTVectors(t *testing.T) {
	key := unhex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	e := &eax{block: block, nonceSize: 16, tagSize: TagSize}
	cases := []struct{ msg, want string }{
		// D.1 example 1: the empty message.
		{"", "bb1d6929e95937287fa37d129b756746"},
		// Example 2: one full block.
		{"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		// Example 3: 40 bytes, so a partial last block.
		{"6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
		// Example 4: four full blocks.
		{"6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411e5fbc1191a0a52ef" +
			"f69f2445df4f9b17ad2b417be66c3710", "51f0bebf7e3b9d92fc49741779363cfe"},
	}
	for i, c := range cases {
		got := e.cmac(unhex(t, c.msg))
		if !bytes.Equal(got, unhex(t, c.want)) {
			t.Errorf("example %d: CMAC = %x, want %s", i+1, got, c.want)
		}
	}
}

// Then EAX itself, against the vectors of the EAX paper.
func TestEAXAgainstThePaperVectors(t *testing.T) {
	cases := []struct{ msg, key, nonce, header, cipher string }{
		{
			msg: "", key: "233952DEE4D5ED5F9B9C6D6FF80FF478",
			nonce: "62EC67F9C3A4A407FCB2A8C49031A8B3", header: "6BFB914FD07EAE6B",
			cipher: "E037830E8389F27B025A2D6527E79D01",
		},
		{
			msg: "F7FB", key: "91945D3F4DCBEE0BF45EF52255F095A4",
			nonce: "BECAF043B0A23D843194BA972C66DEBD", header: "FA3BFD4806EB53FA",
			cipher: "19DD5C4C9331049D0BDAB0277408F67967E5",
		},
		{
			msg: "1A47CB4933", key: "01F74AD64077F2E704C0F60ADA3DD523",
			nonce: "70C3DB4F0D26368400A10ED05D2BFF5E", header: "234A3463C1264AC6",
			cipher: "D851D5BAE03A59F238A23E39199DC9266626C40F80",
		},
	}
	for i, c := range cases {
		block, err := aes.NewCipher(unhex(t, c.key))
		if err != nil {
			t.Fatal(err)
		}
		nonce := unhex(t, c.nonce)
		a, err := New(block, len(nonce))
		if err != nil {
			t.Fatal(err)
		}
		got := a.Seal(nil, nonce, unhex(t, c.msg), unhex(t, c.header))
		if !bytes.Equal(got, unhex(t, c.cipher)) {
			t.Errorf("vector %d: Seal = %X, want %s", i+1, got, c.cipher)
			continue
		}
		back, err := a.Open(nil, nonce, got, unhex(t, c.header))
		if err != nil {
			t.Errorf("vector %d: Open: %v", i+1, err)
			continue
		}
		if !bytes.Equal(back, unhex(t, c.msg)) {
			t.Errorf("vector %d: Open = %X, want %s", i+1, back, c.msg)
		}
	}
}

// Every field is authenticated, so changing any of them is a message
// that does not open.
func TestNothingOpensWhenAnythingChanges(t *testing.T) {
	block, err := aes.NewCipher(bytes.Repeat([]byte{7}, 16))
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(block, 16)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{1}, 16)
	header := []byte("length-prefix")
	sealed := a.Seal(nil, nonce, []byte("what the desktop showed"), header)

	if _, err := a.Open(nil, nonce, sealed, header); err != nil {
		t.Fatalf("an untouched message did not open: %v", err)
	}
	for _, c := range []struct {
		name           string
		nonce, ct, hdr []byte
	}{
		{"a changed byte", nonce, flip(sealed, 0), header},
		{"a changed tag", nonce, flip(sealed, len(sealed)-1), header},
		{"another nonce", flip(nonce, 15), sealed, header},
		{"another header", nonce, sealed, []byte("length-prefiy")},
		{"a truncated message", nonce, sealed[:len(sealed)-1], header},
		{"nothing at all", nonce, nil, header},
	} {
		if _, err := a.Open(nil, c.nonce, c.ct, c.hdr); !errors.Is(err, ErrOpen) {
			t.Errorf("%s opened (%v)", c.name, err)
		}
	}
}

// Seal appends, so a caller can build a framed message in one buffer.
func TestSealAppendsToItsDestination(t *testing.T) {
	block, _ := aes.NewCipher(bytes.Repeat([]byte{3}, 16))
	a, err := New(block, 16)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{2}, 16)
	head := []byte{0x00, 0x05}
	out := a.Seal(head, nonce, []byte("hello"), head)
	if !bytes.Equal(out[:2], head) {
		t.Fatalf("the destination was overwritten: %x", out[:2])
	}
	if got := a.Overhead(); len(out) != 2+5+got {
		t.Errorf("%d bytes, want %d", len(out), 2+5+got)
	}
	back, err := a.Open(nil, nonce, out[2:], head)
	if err != nil || string(back) != "hello" {
		t.Errorf("opened %q (%v)", back, err)
	}
}

func flip(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 0x80
	return out
}
