package domain

import (
	"bytes"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestNewID_Version_Variant(t *testing.T) {
	id := NewID()
	if v := id[6] >> 4; v != 0x7 {
		t.Errorf("version: got 0x%x, want 0x7", v)
	}
	if vt := id[8] >> 6; vt != 0x2 {
		t.Errorf("variant: got 0x%x, want 0x2 (10b)", vt)
	}
}

func TestNewID_Timestamp(t *testing.T) {
	before := time.Now().UnixMilli()
	id := NewID()
	after := time.Now().UnixMilli()
	ts := id.TimestampMS()
	if ts < before || ts > after+1 {
		t.Errorf("timestamp out of range: %d not in [%d, %d]", ts, before, after)
	}
}

func TestNewID_Monotonic_SingleGoroutine(t *testing.T) {
	const n = 10000
	ids := make([]ID, n)
	for i := range ids {
		ids[i] = NewID()
	}
	for i := 1; i < n; i++ {
		if bytes.Compare(ids[i-1][:], ids[i][:]) >= 0 {
			t.Fatalf("non-monotonic at i=%d: %s vs %s", i, ids[i-1], ids[i])
		}
	}
}

func TestNewID_Monotonic_Concurrent(t *testing.T) {
	const goroutines = 50
	const perG = 200
	all := make([]ID, 0, goroutines*perG)
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			batch := make([]ID, perG)
			for i := 0; i < perG; i++ {
				batch[i] = NewID()
			}
			mu.Lock()
			all = append(all, batch...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	// Concurrent generation cannot guarantee a strict order across goroutines,
	// but ALL ids must be unique. Sort and check.
	sort.Slice(all, func(i, j int) bool {
		return bytes.Compare(all[i][:], all[j][:]) < 0
	})
	for i := 1; i < len(all); i++ {
		if all[i-1] == all[i] {
			t.Fatalf("duplicate ID at i=%d: %s", i, all[i])
		}
	}
}

func TestParseID_Roundtrip(t *testing.T) {
	id := NewID()
	hyphenated := id.String()
	parsed, err := ParseID(hyphenated)
	if err != nil {
		t.Fatalf("ParseID: %v", err)
	}
	if parsed != id {
		t.Errorf("roundtrip: got %s, want %s", parsed, id)
	}

	// Non-hyphenated form
	hex32 := id.HexString()
	parsed2, err := ParseID(hex32)
	if err != nil {
		t.Fatalf("ParseID hex: %v", err)
	}
	if parsed2 != id {
		t.Errorf("hex roundtrip: got %s, want %s", parsed2, id)
	}
}

func TestParseID_Invalid(t *testing.T) {
	cases := []string{
		"",
		"not-a-uuid",
		"00000000-0000-0000-0000",
		"00000000-0000-0000-0000-00000000000G", // not hex
		"00000000-0000-0000-0000-0000000000001",
	}
	for _, c := range cases {
		if _, err := ParseID(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestID_ScanValue(t *testing.T) {
	id := NewID()
	v, err := id.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	bs, ok := v.([]byte)
	if !ok || len(bs) != 16 {
		t.Fatalf("Value did not return 16-byte []byte: %T %v", v, v)
	}
	var got ID
	if err := got.Scan(bs); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got != id {
		t.Errorf("scan/value roundtrip: %s vs %s", got, id)
	}

	// Scan from string form
	var got2 ID
	if err := got2.Scan(id.String()); err != nil {
		t.Fatalf("Scan from string: %v", err)
	}
	if got2 != id {
		t.Errorf("scan-string mismatch")
	}

	// Scan nil
	var got3 ID
	if err := got3.Scan(nil); err != nil {
		t.Fatalf("Scan nil: %v", err)
	}
	if !got3.IsZero() {
		t.Errorf("Scan nil should produce Zero ID")
	}
}

func TestID_TextMarshal(t *testing.T) {
	id := NewID()
	b, err := id.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if string(b) != id.String() {
		t.Errorf("MarshalText: got %q, want %q", b, id.String())
	}
	var got ID
	if err := got.UnmarshalText(b); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if got != id {
		t.Errorf("text roundtrip mismatch")
	}
}

func TestIPHelpers(t *testing.T) {
	// IPv4
	a4, _ := netip.ParseAddr("10.78.0.1")
	b4 := IPToBytes(a4)
	if len(b4) != 4 {
		t.Errorf("v4 bytes: %d", len(b4))
	}
	a4r, err := IPFromBytes(b4)
	if err != nil || a4r != a4 {
		t.Errorf("v4 roundtrip: %v %v", a4r, err)
	}

	// IPv6
	a6, _ := netip.ParseAddr("fd5e:7c2a:d8e1::1")
	b6 := IPToBytes(a6)
	if len(b6) != 16 {
		t.Errorf("v6 bytes: %d", len(b6))
	}
	a6r, err := IPFromBytes(b6)
	if err != nil || a6r != a6 {
		t.Errorf("v6 roundtrip: %v %v", a6r, err)
	}

	// IPv6 v4-mapped should unmap
	mapped := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 78, 0, 1}
	r, err := IPFromBytes(mapped)
	if err != nil {
		t.Fatalf("mapped: %v", err)
	}
	if !r.Is4() {
		t.Errorf("expected mapped to unmap to v4, got %v", r)
	}
}
