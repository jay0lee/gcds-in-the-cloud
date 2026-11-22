package proxy

import (
	"io"
	"log/slog"
	"strings"
)

var sensitiveLogKeys = map[string]struct{}{
	"authorization":       {},
	"proxy_authorization": {},
	"proxy-authorization": {},
	"dpop":                {},
	"cookie":              {},
	"set-cookie":          {},
	"access_token":        {},
	"refresh_token":       {},
	"id_token":            {},
	"assertion":           {},
	"signed_jwt":          {},
	"signedjwt":           {},
	"code":                {},
	"client_secret":       {},
	"private_key":         {},
}

// NewRedactingLogger constructs a structured JSON slog.Logger that scrubs credentials, tokens,
// authorization codes, and assertions before emitting audit events.
func NewRedactingLogger(w io.Writer, levelStr string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: lvl,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if _, sensitive := sensitiveLogKeys[strings.ToLower(a.Key)]; sensitive {
				return slog.String(a.Key, "[REDACTED]")
			}
			return a
		},
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}
