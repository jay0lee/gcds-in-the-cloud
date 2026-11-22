package authswap

import (
	"context"
	"net/http"
)

// Strategy transforms an outbound HTTP request by stripping client-supplied 3-legged OAuth
// credentials and injecting the configured keyless Service Account or ADC credential.
type Strategy interface {
	Name() string
	InterceptTokenEndpoint() bool
	Apply(ctx context.Context, req *http.Request) error
}

// SanitizeInbound3LO strips all client-supplied 3-legged OAuth headers, cookies, and query
// parameters from req prior to injecting proxy-managed credentials.
func SanitizeInbound3LO(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Del("Authorization")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("X-Goog-AuthUser")
	req.Header.Del("Cookie")

	if req.URL != nil && req.URL.RawQuery != "" {
		q := req.URL.Query()
		modified := false
		for _, key := range []string{"access_token", "bearer_token"} {
			if q.Has(key) {
				q.Del(key)
				modified = true
			}
		}
		if modified {
			req.URL.RawQuery = q.Encode()
		}
	}
}
