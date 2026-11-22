package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jay0lee/gcds-in-the-cloud/internal/ca"
	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
	"golang.org/x/net/http2"
)

type ctxKeyClientProfile struct{}

// Server hosts the dual-mode local authentication proxy:
//  1. Explicit Forward HTTP CONNECT MITM Proxy (for closed-source apps like GCDS)
//  2. Local Reverse Proxy (for SDKs/CLIs supporting endpoint URL overrides without MITM CA trust)
type Server struct {
	cfg       *config.Config
	engine    *Engine
	authority *ca.Authority
	dialFunc  func(ctx context.Context, network, addr string) (net.Conn, error)
	logger    *slog.Logger

	mu          sync.Mutex
	connectLn   net.Listener
	reverseLn   net.Listener
	connectSrv  *http.Server
	reverseSrv  *http.Server
	h2TunnelSrv *http2.Server
}

type ServerOptions struct {
	Config      *config.Config
	Engine      *Engine
	Authority   *ca.Authority
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	Logger      *slog.Logger
}

func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Config == nil || opts.Engine == nil {
		return nil, errors.New("proxy: Config and Engine are required")
	}
	if opts.Config.Server.ListenConnect != "" && opts.Authority == nil {
		return nil, errors.New("proxy: Authority (Root CA) is required when listen_connect is enabled")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	dialFn := opts.DialContext
	if dialFn == nil {
		d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		dialFn = d.DialContext
	}
	return &Server{
		cfg:         opts.Config,
		engine:      opts.Engine,
		authority:   opts.Authority,
		dialFunc:    dialFn,
		logger:      logger,
		h2TunnelSrv: &http2.Server{},
	}, nil
}

// Start binds configured listeners synchronously (returning bound addresses immediately for callers/tests)
// and serves proxy traffic in background goroutines until Shutdown is called.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.Server.ListenConnect != "" {
		ln, err := listenLocal(s.cfg.Server.ListenConnect, s.cfg.Server.AllowedPeerUIDs, s.logger)
		if err != nil {
			return fmt.Errorf("proxy: bind listen_connect %q: %w", s.cfg.Server.ListenConnect, err)
		}
		s.connectLn = ln
		s.connectSrv = &http.Server{
			Handler:           http.HandlerFunc(s.handleForwardProxy),
			ReadHeaderTimeout: s.cfg.Server.ReadHeaderTimeout,
		}
		go func() {
			if err := s.connectSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Error("proxy: connect server stopped", "err", err)
			}
		}()
	}

	if s.cfg.Server.ListenReverse != "" {
		ln, err := listenLocal(s.cfg.Server.ListenReverse, s.cfg.Server.AllowedPeerUIDs, s.logger)
		if err != nil {
			if s.connectLn != nil {
				_ = s.connectLn.Close()
			}
			return fmt.Errorf("proxy: bind listen_reverse %q: %w", s.cfg.Server.ListenReverse, err)
		}
		s.reverseLn = ln
		s.reverseSrv = &http.Server{
			Handler:           http.HandlerFunc(s.handleReverseProxy),
			ReadHeaderTimeout: s.cfg.Server.ReadHeaderTimeout,
		}
		go func() {
			if err := s.reverseSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Error("proxy: reverse server stopped", "err", err)
			}
		}()
	}
	return nil
}

// ConnectAddr returns the bound forward CONNECT proxy address (empty if disabled).
func (s *Server) ConnectAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.connectLn == nil {
		return ""
	}
	return s.connectLn.Addr().String()
}

// ReverseAddr returns the bound reverse proxy address (empty if disabled).
func (s *Server) ReverseAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reverseLn == nil {
		return ""
	}
	return s.reverseLn.Addr().String()
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	cSrv := s.connectSrv
	rSrv := s.reverseSrv
	s.mu.Unlock()

	var errs []error
	if cSrv != nil {
		if err := cSrv.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if rSrv != nil {
		if err := rSrv.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Server) handleForwardProxy(w http.ResponseWriter, r *http.Request) {
	clientProfile, err := s.engine.AuthenticateCaller(r.Header.Get("Proxy-Authorization"))
	if err != nil {
		w.Header().Set("Proxy-Authenticate", `Basic realm="go-oauth-proxy"`)
		http.Error(w, "407 Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	if r.Method == http.MethodConnect {
		s.handleConnectTunnel(w, r, clientProfile)
		return
	}

	// Plain HTTP absolute-URI proxy request (if any)
	if r.URL.Scheme == "" || r.URL.Host == "" {
		http.Error(w, "400 Bad Request: forward proxy requires CONNECT or absolute URI", http.StatusBadRequest)
		return
	}
	if !s.cfg.IsHostAllowed(r.URL.Hostname()) {
		http.Error(w, "403 Forbidden: host not in server.allowed_hosts", http.StatusForbidden)
		return
	}
	s.executeAndWriteResponse(w, r, clientProfile)
}

func (s *Server) handleConnectTunnel(w http.ResponseWriter, r *http.Request, clientProfile string) {
	targetHostPort := r.Host
	if targetHostPort == "" {
		targetHostPort = r.URL.Host
	}
	hostOnly := stripPort(targetHostPort)
	if _, _, err := net.SplitHostPort(targetHostPort); err != nil {
		targetHostPort = net.JoinHostPort(hostOnly, "443")
	}

	if !s.cfg.IsHostAllowed(hostOnly) {
		if !s.cfg.Server.PassthroughUnmatched {
			s.logger.Warn("proxy: blocked CONNECT to non-allowlisted host", "host", hostOnly, "client", clientProfile)
			http.Error(w, "403 Forbidden: host not in server.allowed_hosts", http.StatusForbidden)
			return
		}
		s.blindTCPSplice(w, r, targetHostPort)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "500 Internal Server Error: connection hijacking unsupported", http.StatusInternalServerError)
		return
	}
	rawConn, brw, err := hj.Hijack()
	if err != nil {
		return
	}

	if _, err := brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = rawConn.Close()
		return
	}
	if err := brw.Flush(); err != nil {
		_ = rawConn.Close()
		return
	}

	tlsConn := tls.Server(rawConn, s.authority.TLSConfigForTunnel(hostOnly))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		s.logger.Debug("proxy: client TLS handshake inside CONNECT tunnel failed", "host", hostOnly, "err", err)
		_ = tlsConn.Close()
		return
	}

	tunnelHandler := http.HandlerFunc(func(tw http.ResponseWriter, tr *http.Request) {
		cloned := tr.Clone(context.WithValue(tr.Context(), ctxKeyClientProfile{}, clientProfile))
		cloned.URL.Scheme = "https"
		if cloned.URL.Host == "" {
			if tr.Host != "" {
				cloned.URL.Host = tr.Host
			} else {
				cloned.URL.Host = hostOnly
			}
		}
		if !s.cfg.IsHostAllowed(cloned.URL.Hostname()) {
			http.Error(tw, "403 Forbidden: SNI/Host mismatch outside server.allowed_hosts", http.StatusForbidden)
			return
		}
		s.executeAndWriteResponse(tw, cloned, clientProfile)
	})

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		s.h2TunnelSrv.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: tunnelHandler})
		_ = tlsConn.Close()
		return
	}

	innerSrv := &http.Server{
		Handler:           tunnelHandler,
		ReadHeaderTimeout: s.cfg.Server.ReadHeaderTimeout,
		IdleTimeout:       60 * time.Second,
	}
	_ = innerSrv.Serve(newSingleConnListener(tlsConn))
}

func (s *Server) blindTCPSplice(w http.ResponseWriter, r *http.Request, targetHostPort string) {
	upConn, err := s.dialFunc(r.Context(), "tcp", targetHostPort)
	if err != nil {
		http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upConn.Close()
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	downConn, brw, err := hj.Hijack()
	if err != nil {
		_ = upConn.Close()
		return
	}
	_, _ = brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = brw.Flush()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upConn, downConn)
		_ = upConn.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(downConn, upConn)
		_ = downConn.Close()
	}()
	wg.Wait()
}

// handleReverseProxy accepts plain local HTTP requests and maps them to upstream HTTPS Google APIs:
//   - GET /healthz -> readiness check
//   - /https/<google-host>/<path...> -> https://<google-host>/<path...>
//   - X-Target-Host: <google-host> + /<path...> -> https://<google-host>/<path...>
func (s *Server) handleReverseProxy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":   "ok",
			"dpop_jkt": s.engine.DPoPThumbprint(),
		})
		return
	}

	clientProfile, err := s.engine.AuthenticateCaller(r.Header.Get("Proxy-Authorization"))
	if err != nil {
		w.Header().Set("Proxy-Authenticate", `Basic realm="go-oauth-proxy"`)
		http.Error(w, "407 Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	targetHost, targetPath, ok := resolveReverseTarget(r)
	if !ok {
		http.Error(w, "400 Bad Request: use /https/<host>/<path> or X-Target-Host header", http.StatusBadRequest)
		return
	}
	if !s.cfg.IsHostAllowed(targetHost) {
		http.Error(w, "403 Forbidden: host not in server.allowed_hosts", http.StatusForbidden)
		return
	}

	cloned := r.Clone(r.Context())
	cloned.Header.Del("X-Target-Host")
	cloned.Host = targetHost
	cloned.URL = &url.URL{
		Scheme:   "https",
		Host:     targetHost,
		Path:     targetPath,
		RawQuery: r.URL.RawQuery,
	}
	s.executeAndWriteResponse(w, cloned, clientProfile)
}

func (s *Server) executeAndWriteResponse(w http.ResponseWriter, req *http.Request, clientProfile string) {
	start := time.Now()
	resp, policyName, err := s.engine.HandleRequest(req, clientProfile)
	if err != nil {
		s.logger.Error("proxy: upstream/auth error",
			"policy", policyName,
			"client", clientProfile,
			"method", req.Method,
			"host", req.URL.Host,
			"path", req.URL.Path,
			"err", err,
		)
		http.Error(w, "502 Bad Gateway: authentication proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	stripHopByHopHeaders(resp.Header)
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	s.logger.Info("proxy: completed request",
		"policy", policyName,
		"client", clientProfile,
		"method", req.Method,
		"host", req.URL.Host,
		"path", req.URL.Path,
		"status", resp.StatusCode,
		"latency_ms", time.Since(start).Milliseconds(),
	)
}

func resolveReverseTarget(r *http.Request) (host, path string, ok bool) {
	if strings.HasPrefix(r.URL.Path, "/https/") {
		rest := strings.TrimPrefix(r.URL.Path, "/https/")
		slashIdx := strings.IndexByte(rest, '/')
		if slashIdx == -1 {
			if rest == "" {
				return "", "", false
			}
			return rest, "/", true
		}
		return rest[:slashIdx], rest[slashIdx:], true
	}
	if xHost := strings.TrimSpace(r.Header.Get("X-Target-Host")); xHost != "" {
		p := r.URL.Path
		if p == "" {
			p = "/"
		}
		return xHost, p, true
	}
	return "", "", false
}

type peerCheckingListener struct {
	net.Listener
	allowedUIDs []uint32
	logger      *slog.Logger
}

func (l *peerCheckingListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if err := verifyPeerUID(c, l.allowedUIDs); err != nil {
			l.logger.Warn("proxy: rejected local caller failing peer UID check", "err", err)
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

func listenLocal(addr string, allowedUIDs []uint32, logger *slog.Logger) (net.Listener, error) {
	if strings.HasPrefix(addr, "unix://") {
		sockPath := strings.TrimPrefix(addr, "unix://")
		_ = os.Remove(sockPath)
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			return nil, err
		}
		_ = os.Chmod(sockPath, 0o600)
		return &peerCheckingListener{Listener: ln, allowedUIDs: allowedUIDs, logger: logger}, nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &peerCheckingListener{Listener: ln, allowedUIDs: allowedUIDs, logger: logger}, nil
}

type closeTrackingConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *closeTrackingConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

type singleConnListener struct {
	mu     sync.Mutex
	conn   *closeTrackingConn
	served bool
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	return &singleConnListener{
		conn: &closeTrackingConn{
			Conn: c,
			done: make(chan struct{}),
		},
	}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.served && l.conn != nil {
		l.served = true
		c := l.conn
		l.mu.Unlock()
		return c, nil
	}
	done := l.conn.done
	l.mu.Unlock()

	<-done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return &net.TCPAddr{}
}
