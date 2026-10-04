package proto

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"silenttunnel/internal/crypto"
)

// ErrBadProbe marks connections that failed authentication: the caller has
// already been served the decoy and must not retry.
var ErrBadProbe = errors.New("silent: unauthorized probe")

func headerAAD(salt []byte) []byte {
	out := make([]byte, 0, 5+len(salt))
	out = append(out, Magic[:]...)
	out = append(out, Version)
	out = append(out, salt...)
	return out
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return b
}

// ClientHandshake runs on the node over an established TLS connection. It
// proves knowledge of the token, verifies the hub's proof, checks clock skew
// and returns the AEAD-framed connection ready for smux.
func ClientHandshake(conn net.Conn, token []byte) (net.Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(DialTimeout)); err != nil {
		return nil, err
	}
	clientSalt := randomBytes(16)
	kAuth, err := crypto.AuthKey(token, clientSalt)
	if err != nil {
		return nil, err
	}
	proofAEAD, err := chacha20poly1305.New(kAuth)
	if err != nil {
		return nil, err
	}

	echoNonce := randomBytes(24)
	payload := make([]byte, 8+24)
	binary.BigEndian.PutUint64(payload, uint64(time.Now().Unix()))
	copy(payload[8:], echoNonce)

	var zero [12]byte
	hello := make([]byte, 0, ClientHelloLen)
	hello = append(hello, Magic[:]...)
	hello = append(hello, Version)
	hello = append(hello, clientSalt...)
	hello = proofAEAD.Seal(hello, zero[:], payload, headerAAD(clientSalt))
	if _, err := conn.Write(hello); err != nil {
		return nil, fmt.Errorf("send hello: %w", err)
	}

	reply := make([]byte, ServerReplyLen)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, fmt.Errorf("read server reply: %w", err)
	}
	serverSalt := reply[:16]
	kC2S, kS2C, err := crypto.DataKeys(token, clientSalt, serverSalt)
	if err != nil {
		return nil, err
	}
	s2c, err := chacha20poly1305.New(kS2C)
	if err != nil {
		return nil, err
	}
	plain, err := s2c.Open(nil, zero[:], reply[16:], headerAAD(serverSalt))
	if err != nil || len(plain) != 32 {
		return nil, errors.New("hub authentication failed (wrong token or probe)")
	}
	if subtle.ConstantTimeCompare(plain[8:], echoNonce) != 1 {
		return nil, errors.New("hub echo mismatch")
	}
	hubTime := time.Unix(int64(binary.BigEndian.Uint64(plain)), 0)
	if skew := time.Since(hubTime); skew > ClockSkew || skew < -ClockSkew {
		return nil, fmt.Errorf("clock skew to hub is %s (limit %s) — sync the server clock", skew.Round(time.Second), ClockSkew)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return crypto.NewAEADConn(conn, kC2S, kS2C)
}

// ServerHandshake runs on the hub over an accepted TLS connection. Any
// failure serves the decoy HTTP answer and returns ErrBadProbe.
func ServerHandshake(conn net.Conn, token []byte) (net.Conn, error) {
	if err := conn.SetReadDeadline(time.Now().Add(AuthReadTimeout)); err != nil {
		Decoy(conn)
		return nil, err
	}
	hello := make([]byte, ClientHelloLen)
	if _, err := io.ReadFull(conn, hello); err != nil {
		Decoy(conn)
		return nil, fmt.Errorf("%w: %v", ErrBadProbe, err)
	}
	if !bytes.Equal(hello[:4], Magic[:]) || hello[4] != Version {
		Decoy(conn)
		return nil, fmt.Errorf("%w: bad magic/version", ErrBadProbe)
	}
	clientSalt := hello[5:21]
	kAuth, err := crypto.AuthKey(token, clientSalt)
	if err != nil {
		Decoy(conn)
		return nil, err
	}
	authAEAD, err := chacha20poly1305.New(kAuth)
	if err != nil {
		Decoy(conn)
		return nil, err
	}
	var zero [12]byte
	plain, err := authAEAD.Open(nil, zero[:], hello[21:], headerAAD(clientSalt))
	if err != nil || len(plain) != 32 {
		Decoy(conn)
		return nil, fmt.Errorf("%w: bad proof", ErrBadProbe)
	}
	nodeTime := time.Unix(int64(binary.BigEndian.Uint64(plain)), 0)
	if skew := time.Since(nodeTime); skew > ClockSkew || skew < -ClockSkew {
		Decoy(conn)
		return nil, fmt.Errorf("node clock skew %s exceeds limit", skew.Round(time.Second))
	}

	serverSalt := randomBytes(16)
	kC2S, kS2C, err := crypto.DataKeys(token, clientSalt, serverSalt)
	if err != nil {
		Decoy(conn)
		return nil, err
	}
	s2c, err := chacha20poly1305.New(kS2C)
	if err != nil {
		Decoy(conn)
		return nil, err
	}
	ackPayload := make([]byte, 8+24)
	binary.BigEndian.PutUint64(ackPayload, uint64(time.Now().Unix()))
	copy(ackPayload[8:], plain[8:])
	reply := append([]byte{}, serverSalt...)
	reply = s2c.Seal(reply, zero[:], ackPayload, headerAAD(serverSalt))
	if err := conn.SetWriteDeadline(time.Now().Add(AuthReadTimeout)); err != nil {
		Decoy(conn)
		return nil, err
	}
	if _, err := conn.Write(reply); err != nil {
		return nil, fmt.Errorf("send server reply: %w", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return crypto.NewAEADConn(conn, kS2C, kC2S)
}
