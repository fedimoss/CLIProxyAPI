package cliproxy

import (
	"context"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// serviceCoreAuthHook bridges core auth lifecycle events into service runtime sync.
type serviceCoreAuthHook struct {
	next    coreauth.Hook
	service *Service
}

// OnAuthRegistered forwards registration events.
func (h *serviceCoreAuthHook) OnAuthRegistered(ctx context.Context, auth *coreauth.Auth) {
	if h == nil {
		return
	}
	if h.next != nil {
		h.next.OnAuthRegistered(ctx, auth)
	}
}

// OnAuthUpdated forwards update events and reconciles runtime registration.
func (h *serviceCoreAuthHook) OnAuthUpdated(ctx context.Context, auth *coreauth.Auth) {
	if h == nil {
		return
	}
	if h.next != nil {
		h.next.OnAuthUpdated(ctx, auth)
	}
	if h.service != nil {
		h.service.reconcileRuntimeAuthRegistration(auth)
	}
}

// OnResult forwards execution result events.
func (h *serviceCoreAuthHook) OnResult(ctx context.Context, result coreauth.Result) {
	if h == nil {
		return
	}
	if h.next != nil {
		h.next.OnResult(ctx, result)
	}
}

// attachCoreAuthHook installs the service-aware hook on the core manager.
func (s *Service) attachCoreAuthHook() {
	if s == nil || s.coreManager == nil {
		return
	}
	current := s.coreManager.Hook()
	if existing, ok := current.(*serviceCoreAuthHook); ok && existing != nil && existing.service == s {
		return
	}
	s.coreManager.SetHook(&serviceCoreAuthHook{
		next:    current,
		service: s,
	})
}

// reconcileRuntimeAuthRegistration keeps model registrations aligned with auth status.
func (s *Service) reconcileRuntimeAuthRegistration(auth *coreauth.Auth) {
	if s == nil || s.coreManager == nil || auth == nil || auth.ID == "" {
		return
	}
	if !coreauth.IsAuthActiveForRouting(auth) {
		GlobalModelRegistry().UnregisterClient(auth.ID)
		s.coreManager.RefreshSchedulerEntry(auth.ID)
		return
	}
	s.ensureExecutorsForAuth(auth)
	s.completeModelRegistrationForAuth(context.Background(), auth)
}
