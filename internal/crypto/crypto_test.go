package crypto

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
)

func TestTokenRoundtrip(t *testing.T) {
	p := &Pairing{
		V:    1,
		Host: "5.6.7.8",
		Port: 443,
		SNI:  "cloudflare.com",
		Key:  make([]byte, 32),
		FP:   "ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34",
	}
	p.Key[0] = 42
	p.Maps = [][2]int{{2087, 8443}, {44301, 44301}}

	s, err := EncodeToken(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(s) < 10 || s[:4] != TokenPrefix {
		t.Fatalf("token missing prefix: %q", s)
	}
	q, err := DecodeToken(s + "  \n")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if q.Host != p.Host || q.Port != p.Port || q.SNI != p.SNI || !bytes.Equal(q.Key, p.Key) || q.FP != p.FP {
		t.Fatalf("roundtrip mismatch: %+v", q)
	}
	if q.RemoteFor(2087) != 8443 || q.RemoteFor(1234) != 1234 {
		t.Fatalf("RemoteFor mapping wrong: %v", q.Maps)
	}
}

func TestDecodeTokenRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "xx", "st1_", "st1_###", "st1_eyJhIjoxfQ"} {
		if _, err := DecodeToken(bad); err == nil {
			t.Fatalf("DecodeToken(%q) should fail", bad)
		}
	}
}

func TestDataKeysDeterministic(t *testing.T) {
	tok := []byte("shared-secret-token")
	cs := bytes.Repeat([]byte{1}, 16)
	ss := bytes.Repeat([]byte{2}, 16)
	a1, b1, err := DataKeys(tok, cs, ss)
	if err != nil {
		t.Fatal(err)
	}
	a2, b2, _ := DataKeys(tok, cs, ss)
	if !bytes.Equal(a1, a2) || !bytes.Equal(b1, b2) {
		t.Fatal("DataKeys not deterministic")
	}
	if bytes.Equal(a1, b1) {
		t.Fatal("direction keys must differ")
	}
	if len(a1) != KeyLen || len(b1) != KeyLen {
		t.Fatal("wrong key length")
	}
}

// TestAEADConnRoundtrip drives a full duplex session over net.Pipe.
func TestAEADConnRoundtrip(t *testing.T) {
	c1, c2 := net.Pipe()
	k1, k2 := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)
	a, err := NewAEADConn(c1, k1, k2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAEADConn(c2, k2, k1)
	if err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte("silent-tunnel-payload!"), 5000) // spans many frames
	go func() {
		if _, err := a.Write(payload); err != nil {
			t.Errorf("write: %v", err)
		}
	}()
	got, err := io.ReadAll(io.LimitReader(b, int64(len(payload))))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes", len(got))
	}

	// reverse direction
	go func() {
		_, _ = b.Write([]byte("pong"))
	}()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(a, buf); err != nil {
		t.Fatalf("read reverse: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("reverse mismatch: %q", buf)
	}
}

// TestAEADConnRejectsTamper ensures a flipped ciphertext byte kills the
// connection instead of yielding corrupted plaintext.
func TestAEADConnRejectsTamper(t *testing.T) {
	c1, c2 := net.Pipe()
	k1, k2 := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)
	a, _ := NewAEADConn(c1, k1, k2)
	b, _ := NewAEADConn(c2, k2, k1)

	go func() {
		_, _ = a.Write(bytes.Repeat([]byte("AAAA"), 100))
	}()

	// Read one raw frame (3-byte header + 100 payload + 16 tag) and flip a
	// payload byte; the receiver must refuse to open the frame.
	raw := make([]byte, 3+100+16)
	if _, err := io.ReadFull(c2, raw); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	raw[20] ^= 0xff
	if _, err := b.Read(make([]byte, 10)); err == nil {
		t.Fatal("tampered frame must fail to open")
	}
	_ = a.Close()
	_ = b.Close()
}

func TestCertGenerateAndFingerprint(t *testing.T) {
	cert, err := GenerateSelfSigned("cloudflare.com")
	if err != nil {
		t.Fatal(err)
	}
	fp := Fingerprint(cert)
	if len(fp) != 64 {
		t.Fatalf("fingerprint length: %d", len(fp))
	}
	cert2, err := GenerateSelfSigned("cloudflare.com")
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(cert2) == fp {
		t.Fatal("two generated certs must differ")
	}
	if cert.Leaf.Subject.CommonName != "cloudflare.com" {
		t.Fatal("CN must carry the SNI")
	}
	var _ tls.Certificate = cert
}
