package policies

import (
	"errors"
	"testing"
)

func TestNormalizeCIDR(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"v4 already masked", "10.10.0.0/16", "10.10.0.0/16", false},
		{"v4 needs masking", "10.10.0.5/16", "10.10.0.0/16", false},
		{"v4 host route", "10.10.0.5/32", "10.10.0.5/32", false},
		{"v4 default", "0.0.0.0/0", "0.0.0.0/0", false},
		{"v6 normal", "2001:db8::/32", "2001:db8::/32", false},
		{"v6 needs masking", "2001:db8:1::1/32", "2001:db8::/32", false},
		{"trim whitespace", "  10.10.0.0/16  ", "10.10.0.0/16", false},
		{"missing prefix", "10.10.0.0", "", true},
		{"invalid bits", "10.10.0.0/33", "", true},
		{"garbage", "not-a-cidr", "", true},
		{"empty", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeCIDR(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("normalizeCIDR(%q) = %q, want error", tc.in, got)
				}
				if err != nil && !errors.Is(err, ErrInvalidCIDR) {
					t.Errorf("normalizeCIDR(%q) error = %v, want wraps ErrInvalidCIDR", tc.in, err)
				}
				return
			}
			if err != nil {
				t.Errorf("normalizeCIDR(%q) error = %v, want nil", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("normalizeCIDR(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBytesEqual(t *testing.T) {
	cases := []struct {
		a, b []byte
		want bool
	}{
		{nil, nil, true},
		{[]byte{}, []byte{}, true},
		{[]byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{[]byte{1, 2, 3}, []byte{1, 2, 4}, false},
		{[]byte{1, 2, 3}, []byte{1, 2}, false},
		{nil, []byte{1}, false},
	}
	for i, tc := range cases {
		got := bytesEqual(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("case %d: bytesEqual(%v, %v) = %v, want %v", i, tc.a, tc.b, got, tc.want)
		}
	}
}
