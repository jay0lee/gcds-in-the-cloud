//go:build linux

package keystore

import "github.com/google/go-tpm/tpm2/transport"

func openTPMDevice(devicePath string) (transport.TPMCloser, error) {
	if devicePath != "" {
		return transport.OpenTPM(devicePath)
	}
	return transport.OpenTPM()
}
