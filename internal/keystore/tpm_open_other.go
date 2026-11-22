//go:build !linux

package keystore

import "github.com/google/go-tpm/tpm2/transport"

func openTPMDevice(_ string) (transport.TPMCloser, error) {
	return transport.OpenTPM()
}
