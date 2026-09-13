package relay

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// conn is one peer's WebSocket connection. We hand-roll a minimal WS
// reader/writer rather than pulling in gorilla/websocket because we
// only need a tiny subset:
//   - server-side accept of GET-with-Upgrade
//   - binary frames in/out
//   - ping/pong keepalive
//
// The full RFC 6455 surface area (extensions, fragments, compression,
// origin checks) is not relevant to a private relay, and adding it
// would mean another dependency in a project that's deliberately
// keeping its dep set tiny.
//
// Wire format inside each WS binary message:
//
//	+------+----------+--------+----------+------+
//	| 1B   | 2B (BE)  |  N B   | 2B (BE)  | M B  |
//	+------+----------+--------+----------+------+
//	| type | hdr_len  | header | data_len | data |
//	+------+----------+--------+----------+------+
//
//	type     : frameType byte
//	header   : opaque bytes (e.g. session ID for routed packets)
//	data     : opaque payload (typically WireGuard ciphertext)
type conn struct {
	netConn net.Conn
	reader  *bufio.Reader
	writeMu sync.Mutex
	closed  bool
}

func acceptWebSocket(w http.ResponseWriter, r *http.Request) (*conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("not a WebSocket upgrade")
	}
	wsKey := r.Header.Get("Sec-WebSocket-Key")
	if wsKey == "" {
		return nil, errors.New("missing Sec-WebSocket-Key")
	}

	// RFC 6455 section 4.2: the accept value is
	// base64(SHA-1(key + magic)).
	const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(wsKey))
	h.Write([]byte(wsMagic))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("server does not support hijacking")
	}
	netConn, brw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijack: %w", err)
	}

	// Send the upgrade response by hand. http.ResponseWriter is now
	// detached from the connection.
	_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_, _ = brw.WriteString("Upgrade: websocket\r\n")
	_, _ = brw.WriteString("Connection: Upgrade\r\n")
	_, _ = brw.WriteString("Sec-WebSocket-Accept: " + accept + "\r\n\r\n")
	if err := brw.Flush(); err != nil {
		_ = netConn.Close()
		return nil, fmt.Errorf("flush 101: %w", err)
	}
	return &conn{netConn: netConn, reader: brw.Reader}, nil
}

// readFrame reads one WebSocket binary message and parses our app
// framing inside it.
func (c *conn) readFrame() (frameType, []byte, []byte, error) {
	_ = c.netConn.SetReadDeadline(time.Now().Add(connDeadline))

	msg, err := readWSMessage(c.reader)
	if err != nil {
		return 0, nil, nil, err
	}
	if len(msg) < 3 {
		return 0, nil, nil, errors.New("frame too short")
	}
	t := frameType(msg[0])
	hdrLen := binary.BigEndian.Uint16(msg[1:3])
	if int(3+hdrLen+2) > len(msg) {
		return 0, nil, nil, errors.New("frame header exceeds message")
	}
	header := msg[3 : 3+int(hdrLen)]
	dataLenStart := 3 + int(hdrLen)
	dataLen := binary.BigEndian.Uint16(msg[dataLenStart : dataLenStart+2])
	dataStart := dataLenStart + 2
	if int(dataStart+int(dataLen)) > len(msg) {
		return 0, nil, nil, errors.New("frame data exceeds message")
	}
	data := msg[dataStart : dataStart+int(dataLen)]
	return t, header, data, nil
}

// sendFrame writes one binary WebSocket message containing our app frame.
// Safe for concurrent use.
func (c *conn) sendFrame(t frameType, header, data []byte) error {
	if len(header) > 0xFFFF {
		return errors.New("header too large")
	}
	if len(data) > 0xFFFF {
		return errors.New("data too large")
	}
	buf := make([]byte, 0, 5+len(header)+len(data))
	buf = append(buf, byte(t))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(header)))
	buf = append(buf, header...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(data)))
	buf = append(buf, data...)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return errors.New("conn closed")
	}
	_ = c.netConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return writeWSMessage(c.netConn, buf)
}

func (c *conn) close() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.netConn.Close()
}

// ----- Minimal RFC 6455 framing --------------------------------------------
//
// We accept and produce single-frame BINARY (opcode 0x2) messages only.
// Continuation frames are rejected. Client-to-server messages are masked
// per the RFC; server-to-client are not.

const (
	wsOpcodeBinary = 0x2
	wsOpcodeClose  = 0x8
	wsOpcodePing   = 0x9
	wsOpcodePong   = 0xA
)

// readWSMessage reads one binary frame and returns its payload.
// Returns io.EOF on a graceful close.
func readWSMessage(r *bufio.Reader) ([]byte, error) {
	for {
		hdr1, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		hdr2, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		fin := hdr1&0x80 != 0
		opcode := hdr1 & 0x0F
		masked := hdr2&0x80 != 0
		ln64 := uint64(hdr2 & 0x7F)
		switch ln64 {
		case 126:
			var l16 [2]byte
			if _, err := io.ReadFull(r, l16[:]); err != nil {
				return nil, err
			}
			ln64 = uint64(binary.BigEndian.Uint16(l16[:]))
		case 127:
			var l64 [8]byte
			if _, err := io.ReadFull(r, l64[:]); err != nil {
				return nil, err
			}
			ln64 = binary.BigEndian.Uint64(l64[:])
		}
		if ln64 > 1<<20 {
			return nil, errors.New("frame too large")
		}
		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(r, maskKey[:]); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, ln64)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}
		switch opcode {
		case wsOpcodeBinary:
			if !fin {
				return nil, errors.New("fragmented frames not supported")
			}
			return payload, nil
		case wsOpcodeClose:
			return nil, io.EOF
		case wsOpcodePing, wsOpcodePong:
			// Ignore protocol-level pings; our app ping is in-band.
			continue
		default:
			return nil, fmt.Errorf("unsupported WS opcode %x", opcode)
		}
	}
}

// writeWSMessage emits a single unfragmented binary frame.
func writeWSMessage(w net.Conn, payload []byte) error {
	hdr := make([]byte, 0, 10)
	hdr = append(hdr, 0x80|wsOpcodeBinary) // FIN + opcode
	switch {
	case len(payload) <= 125:
		hdr = append(hdr, byte(len(payload)))
	case len(payload) <= 0xFFFF:
		hdr = append(hdr, 126)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(payload)))
	default:
		hdr = append(hdr, 127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(len(payload)))
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return nil
}
