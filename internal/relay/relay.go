// Package relay provides the bidirectional TCP pump shared by hub and node,
// counting wire bytes as they move (not only when the connection closes).
package relay

import (
	"io"
	"net"
	"sync/atomic"
)

// countingReader charges every byte pulled from the underlying reader to
// the counter before handing it downstream.
type countingReader struct {
	r   io.Reader
	ctr *atomic.Uint64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.ctr.Add(uint64(n))
	}
	return n, err
}

// Pipe copies a↔b until either side errors or closes, counting bytes pulled
// from each source. It closes both conns when one direction finishes so the
// other pump unblocks immediately.
func Pipe(a, b net.Conn, in, out *atomic.Uint64) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, &countingReader{r: b, ctr: in})
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, &countingReader{r: a, ctr: out})
		done <- struct{}{}
	}()
	<-done
	_ = a.Close()
	_ = b.Close()
}
