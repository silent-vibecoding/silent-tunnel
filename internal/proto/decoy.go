package proto

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// decoyBody is the standard nginx 404 page; scanners that hit the TLS port
// see an unremarkable web server instead of a tunnel.
const decoyBody = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"

// Decoy writes a plain HTTP 404 answer (over the already-established TLS
// session) and closes the connection. It must be called with the raw TLS
// conn, before any inner-AEAD framing was accepted.
func Decoy(conn net.Conn) {
	resp := fmt.Sprintf("HTTP/1.1 404 Not Found\r\n"+
		"Server: nginx\r\n"+
		"Date: %s\r\n"+
		"Content-Type: text/html\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: keep-alive\r\n\r\n%s",
		time.Now().UTC().Format(http.TimeFormat), len(decoyBody), decoyBody)
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(conn, resp)
	_ = conn.Close()
}
