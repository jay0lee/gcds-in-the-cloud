//go:build !darwin && !linux

package proxy

import "net"

func verifyPeerUID(_ net.Conn, _ []uint32) error {
	return nil
}
