package auth

import (
	"strings"
)

// Remove deletes the auth identified by id from all in-memory caches
// (active, inactive, scheduler, home-runtime). It does NOT touch the
// persistent store — the caller is responsible for database/file cleanup.
func (m *Manager) Remove(id string) {
	if m == nil {
		return
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}

	m.mu.Lock()
	delete(m.auths, id)
	delete(m.inactiveAuths, id)

	// Remove from home-runtime session caches.
	for sessionID, auths := range m.homeRuntimeAuths {
		delete(auths, id)
		if len(auths) == 0 {
			delete(m.homeRuntimeAuths, sessionID)
		}
	}

	if m.scheduler != nil {
		m.scheduler.removeAuth(id)
	}
	m.mu.Unlock()
}
