package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestBearerFrom(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"plain", "Bearer abc.def.ghi", "abc.def.ghi"},
		{"lowercase scheme", "bearer abc.def", "abc.def"},
		{"mixed case", "BeArEr abc", "abc"},
		{"trailing space", "Bearer   abc   ", "abc"},
		{"empty", "", ""},
		{"only scheme", "Bearer ", ""},
		{"wrong scheme", "Basic dXNlcjpwYXNz", ""},
		{"shorter than prefix", "Bear", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/x", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			got := bearerFrom(r)
			if got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}
