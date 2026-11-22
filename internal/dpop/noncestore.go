package dpop

import (
	"container/list"
	"net/url"
	"strings"
	"sync"
	"time"
)

type nonceEntry struct {
	origin    string
	nonce     string
	expiresAt time.Time
}

// NonceStore is a concurrency-safe, bounded-LRU, TTL-expiring cache of server-issued DPoP-Nonce values per origin.
type NonceStore struct {
	mu      sync.Mutex
	maxLen  int
	ttl     time.Duration
	ll      *list.List
	entries map[string]*list.Element
	nowFunc func() time.Time
}

func NewNonceStore(maxEntries int, ttl time.Duration) *NonceStore {
	if maxEntries <= 0 {
		maxEntries = 128
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &NonceStore{
		maxLen:  maxEntries,
		ttl:     ttl,
		ll:      list.New(),
		entries: make(map[string]*list.Element, maxEntries),
		nowFunc: time.Now,
	}
}

// OriginKey normalizes a URL into its scheme://host origin for DPoP-Nonce scoping.
func OriginKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func (s *NonceStore) Get(origin string) string {
	if origin == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	elem, ok := s.entries[origin]
	if !ok {
		return ""
	}
	ent := elem.Value.(*nonceEntry)
	if s.nowFunc().After(ent.expiresAt) {
		s.ll.Remove(elem)
		delete(s.entries, origin)
		return ""
	}
	s.ll.MoveToFront(elem)
	return ent.nonce
}

func (s *NonceStore) Put(origin, nonce string) {
	if origin == "" || nonce == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	exp := s.nowFunc().Add(s.ttl)
	if elem, ok := s.entries[origin]; ok {
		ent := elem.Value.(*nonceEntry)
		ent.nonce = nonce
		ent.expiresAt = exp
		s.ll.MoveToFront(elem)
		return
	}
	for s.ll.Len() >= s.maxLen {
		back := s.ll.Back()
		if back == nil {
			break
		}
		evicted := s.ll.Remove(back).(*nonceEntry)
		delete(s.entries, evicted.origin)
	}
	elem := s.ll.PushFront(&nonceEntry{
		origin:    origin,
		nonce:     nonce,
		expiresAt: exp,
	})
	s.entries[origin] = elem
}
