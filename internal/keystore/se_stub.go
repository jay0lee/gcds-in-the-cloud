//go:build !darwin || !cgo

package keystore

type SecureEnclaveProvider struct {
	MemoryProvider
}

func NewSecureEnclaveProvider() (*SecureEnclaveProvider, error) {
	return nil, ErrUnsupportedPlatform
}
