package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// MaxPayload is the largest plaintext carried by a single frame.
	MaxPayload = 16 * 1024
	// TagSize is the Poly1305 authentication tag size.
	TagSize = 16
	maxFrame = MaxPayload + TagSize
)

// ErrFrameTooLarge is returned when a peer sends a frame longer than allowed.
var ErrFrameTooLarge = errors.New("silent: frame too large")

// AEADConn wraps a net.Conn so that every Write/Read crosses the wire as a
// ChaCha20-Poly1305 frame: [3-byte big-endian length][ciphertext+tag].
// The 12-byte nonce is 4 zero bytes followed by an 8-byte big-endian
// per-direction monotonic counter, so replay and reorder always fail to open.
type AEADConn struct {
	conn net.Conn
	seal cipher.AEAD
	open cipher.AEAD

	wmu sync.Mutex
	seq uint64

	rmu  sync.Mutex
	rseq uint64
	rbuf []byte
}

// NewAEADConn builds the framed connection. sendKey encrypts what this side
// writes; recvKey decrypts what it reads.
func NewAEADConn(conn net.Conn, sendKey, recvKey []byte) (*AEADConn, error) {
	seal, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, fmt.Errorf("aead seal key: %w", err)
	}
	open, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, fmt.Errorf("aead open key: %w", err)
	}
	return &AEADConn{conn: conn, seal: seal, open: open}, nil
}

func (c *AEADConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.rbuf) == 0 {
		if err := c.readFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *AEADConn) readFrame() error {
	var hdr [3]byte
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		return fmt.Errorf("read frame header: %w", err)
	}
	n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	if n < TagSize || n > maxFrame {
		return ErrFrameTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return fmt.Errorf("read frame body: %w", err)
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], c.rseq)
	c.rseq++
	plain, err := c.open.Open(nil, nonce[:], body, nil)
	if err != nil {
		return fmt.Errorf("open frame: %w", err)
	}
	c.rbuf = append(c.rbuf, plain...)
	return nil
}

func (c *AEADConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxPayload {
			chunk = chunk[:MaxPayload]
		}
		if err := c.writeFrame(chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *AEADConn) writeFrame(chunk []byte) error {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], c.seq)
	c.seq++
	lenField := len(chunk) + TagSize
	buf := make([]byte, 3, 3+lenField)
	buf[0] = byte(lenField >> 16)
	buf[1] = byte(lenField >> 8)
	buf[2] = byte(lenField)
	buf = c.seal.Seal(buf, nonce[:], chunk, nil)
	_, err := c.conn.Write(buf)
	return err
}

func (c *AEADConn) Close() error                  { return c.conn.Close() }
func (c *AEADConn) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *AEADConn) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *AEADConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *AEADConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
func (c *AEADConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
