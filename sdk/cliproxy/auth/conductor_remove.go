package auth

import (
	"context"
	"strings"
)

// Remove deletes the auth identified by id from all in-memory caches
// (active, inactive, scheduler, home-runtime). It does NOT touch the
// persistent store; the caller is responsible for database/file cleanup.
func (m *Manager) Remove(ctx context.Context, id string) {
	if m == nil {
		return
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	_ = ctx

	var provider string
	m.mu.Lock()
	if existing, ok := m.authByIDLocked(id); ok && existing != nil {
		provider = strings.TrimSpace(existing.Provider)
	}
	delete(m.auths, id)
	delete(m.inactiveAuths, id)
	if m.modelPoolOffsets != nil {
		delete(m.modelPoolOffsets, id)
	}

	// Remove from home-runtime session caches.
	for sessionID, auths := range m.homeRuntimeAuths {
		if auths == nil {
			continue
		}
		delete(auths, id)
		if len(auths) == 0 {
			delete(m.homeRuntimeAuths, sessionID)
		}
	}
	m.mu.Unlock()

	m.rebuildAPIKeyModelAliasFromRuntimeConfig()
	if m.scheduler != nil {
		m.scheduler.removeAuth(id)
	}
	m.queueRefreshUnschedule(id)
	m.invalidateSessionAffinity(id)

	if provider == "" {
		return
	}
	if exec, ok := m.Executor(provider); ok && exec != nil {
		if closer, okCloser := exec.(ExecutionSessionCloser); okCloser {
			closer.CloseExecutionSession(CloseAllExecutionSessionsID)
		}
	}
}

func (m *Manager) invalidateSessionAffinity(authID string) {
	if m == nil || authID == "" {
		return
	}
	if invalidator, ok := m.selector.(interface{ InvalidateAuth(string) }); ok && invalidator != nil {
		invalidator.InvalidateAuth(authID)
	}
}
