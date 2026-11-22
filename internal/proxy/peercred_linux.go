//go:build linux

package proxy

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func verifyPeerUID(conn net.Conn, allowedUIDs []uint32) error {
	if len(allowedUIDs) == 0 {
		return nil
	}
	uConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil
	}
	rawConn, err := uConn.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if sockErr != nil {
		return sockErr
	}
	for _, allowed := range allowedUIDs {
		if cred.Uid == allowed {
			return nil
		}
	}
	return fmt.Errorf("proxy: caller UID %d is not in allowed_peer_uids", cred.Uid)
}
