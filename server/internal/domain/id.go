// Package domain holds the core types shared across the AidotVpn server.
//
// Two design choices worth flagging up front:
//
//  1. ID is a value type wrapping [16]byte. We pass it around by value
//     because it's small, comparable, and avoids pointer-y pitfalls for
//     map keys / channel sends.
//
//  2. NewID() generates UUIDv7 (RFC 9562). The leading 48 bits are
//     unix-milliseconds, giving the ID near-monotonic ordering — which
//     in turn gives MariaDB clustered-index inserts the same locality
//     benefit as AUTO_INCREMENT, without the cross-shard collision risks.
package domain

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// ID is a 16-byte UUIDv7 identifier.
//
// We deliberately do NOT depend on github.com/google/uuid here. Generating
// UUIDv7 in ~30 lines lets us keep the domain layer dependency-free, which
// matters because every other package will import it.
type ID [16]byte

// Zero is the empty ID. Equivalent to a 16-byte zero slice.
var Zero ID

// monotonic state for UUIDv7. Using a mutex (not atomic) because we need
// to update three fields in lock-step: the last millisecond, the rand_a
// counter, and the previous random tail.
var (
	idMu      sync.Mutex
	lastMS    int64
	lastRandA uint16
)

// NewID returns a fresh UUIDv7 (RFC 9562 §5.7).
//
// Layout:
//
//	bytes 0..5  unix_ts_ms     (48 bits, big-endian)
//	byte  6     ver(4) | rA_h(4)
//	byte  7     rA_l(8)         ← rand_a 12-bit monotonic counter
//	byte  8     var(2) | rB_h(6)
//	bytes 9..15 rB_l(56)
//
// We make rand_a a per-millisecond counter to guarantee strict in-process
// monotonicity even when multiple goroutines call NewID() within the same
// millisecond. The variant bits are set to 10b (RFC 4122 / 9562).
func NewID() ID {
	var b [16]byte

	idMu.Lock()
	now := time.Now().UTC().UnixMilli()
	if now == lastMS {
		// Same ms: increment rand_a (12 bits). On overflow we bump the
		// timestamp by one ms so output stays strictly increasing — this
		// can't happen in practice unless someone calls NewID() >4096
		// times per ms in a single process, but we handle it for safety.
		if lastRandA == 0x0FFF {
			now = lastMS + 1
			lastRandA = 0
		} else {
			lastRandA++
		}
	} else if now < lastMS {
		// Wall clock went backwards (NTP skew). Fall back to lastMS+1
		// rather than emitting a non-monotonic ID.
		now = lastMS + 1
		lastRandA = 0
	} else {
		// New ms: re-seed rand_a from CSPRNG so two processes don't
		// collide just because they happen to start in the same ms.
		var seed [2]byte
		if _, err := rand.Read(seed[:]); err == nil {
			lastRandA = uint16(seed[0])<<4 | uint16(seed[1])>>4
			lastRandA &= 0x0FFF
		} else {
			lastRandA = 0
		}
	}
	lastMS = now
	rA := lastRandA
	idMu.Unlock()

	// timestamp (48 bits, big-endian)
	b[0] = byte(now >> 40)
	b[1] = byte(now >> 32)
	b[2] = byte(now >> 24)
	b[3] = byte(now >> 16)
	b[4] = byte(now >> 8)
	b[5] = byte(now)

	// version 7 + rand_a high nibble
	b[6] = 0x70 | byte(rA>>8)&0x0F
	b[7] = byte(rA)

	// variant 10b + 62 bits of randomness
	if _, err := rand.Read(b[8:]); err != nil {
		// crypto/rand is documented to never return an error in practice.
		// Panic preserves the invariant that NewID always succeeds; alerting
		// on this in production is the operator's job.
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	b[8] = (b[8] & 0x3F) | 0x80

	return ID(b)
}

// String returns the canonical 8-4-4-4-12 hyphenated form.
func (id ID) String() string {
	if id.IsZero() {
		return "00000000-0000-0000-0000-000000000000"
	}
	var buf [36]byte
	hex.Encode(buf[0:8], id[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], id[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], id[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], id[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], id[10:16])
	return string(buf[:])
}

// HexString returns the 32-character non-hyphenated hex form (matches
// MariaDB HEX(...) output for direct comparison).
func (id ID) HexString() string {
	return strings.ToUpper(hex.EncodeToString(id[:]))
}

// Bytes returns a copy of the underlying 16 bytes.
func (id ID) Bytes() []byte {
	out := make([]byte, 16)
	copy(out, id[:])
	return out
}

// IsZero reports whether the ID is all-zeros.
func (id ID) IsZero() bool {
	for _, b := range id {
		if b != 0 {
			return false
		}
	}
	return true
}

// TimestampMS returns the 48-bit timestamp portion as unix milliseconds.
// Returns 0 for v7 IDs whose version nibble is wrong (i.e. not v7).
func (id ID) TimestampMS() int64 {
	// Version is high 4 bits of byte 6.
	if (id[6] >> 4) != 0x7 {
		return 0
	}
	return int64(id[0])<<40 |
		int64(id[1])<<32 |
		int64(id[2])<<24 |
		int64(id[3])<<16 |
		int64(id[4])<<8 |
		int64(id[5])
}

// ParseID parses a hyphenated or non-hyphenated 16-byte hex string.
func ParseID(s string) (ID, error) {
	stripped := strings.ReplaceAll(s, "-", "")
	if len(stripped) != 32 {
		return ID{}, fmt.Errorf("ID: expected 32 hex chars (hyphenated or not), got %d", len(stripped))
	}
	var id ID
	if _, err := hex.Decode(id[:], []byte(stripped)); err != nil {
		return ID{}, fmt.Errorf("ID: %w", err)
	}
	return id, nil
}

// Scan implements sql.Scanner so the type can be read from a BINARY(16)
// column directly into an ID.
func (id *ID) Scan(src any) error {
	if src == nil {
		*id = ID{}
		return nil
	}
	switch v := src.(type) {
	case []byte:
		if len(v) != 16 {
			return fmt.Errorf("ID.Scan: expected 16 bytes, got %d", len(v))
		}
		copy(id[:], v)
		return nil
	case string:
		parsed, err := ParseID(v)
		if err != nil {
			return err
		}
		*id = parsed
		return nil
	default:
		return fmt.Errorf("ID.Scan: cannot convert %T", src)
	}
}

// Value implements driver.Valuer so the type can be written to BINARY(16).
func (id ID) Value() (driver.Value, error) {
	return id.Bytes(), nil
}

// MarshalText implements encoding.TextMarshaler for JSON / log fields.
func (id ID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *ID) UnmarshalText(text []byte) error {
	parsed, err := ParseID(string(text))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// --- IP helpers ---------------------------------------------------------

// IPToBytes returns the 4-byte form for IPv4, 16-byte form for IPv6.
// Returns nil for invalid input.
func IPToBytes(addr netip.Addr) []byte {
	if !addr.IsValid() {
		return nil
	}
	if addr.Is4() {
		b := addr.As4()
		return b[:]
	}
	b := addr.As16()
	return b[:]
}

// IPFromBytes parses 4- or 16-byte address bytes back into a netip.Addr.
func IPFromBytes(b []byte) (netip.Addr, error) {
	switch len(b) {
	case 4:
		return netip.AddrFrom4([4]byte(b)), nil
	case 16:
		return netip.AddrFrom16([16]byte(b)).Unmap(), nil
	default:
		return netip.Addr{}, errors.New("IPFromBytes: expected 4 or 16 bytes")
	}
}
