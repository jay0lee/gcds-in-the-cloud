//go:build darwin

package proxy

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// verifyPeerUID checks the OS kernel-verified UID of a local Unix domain socket caller.
// For AF_INET loopback TCP sockets, kernel peer credential options do not apply and nil is returned.
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
	var cred *unix.Xucred
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
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
