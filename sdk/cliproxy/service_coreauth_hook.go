package cliproxy

import (
	"context"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// serviceCoreAuthHook 将核心认证生命周期事件中继到服务运行时同步。
type serviceCoreAuthHook struct {
	next    coreauth.Hook
	service *Service
}

// OnAuthRegistered 通过钩子链转发注册事件。
func (h *serviceCoreAuthHook) OnAuthRegistered(ctx context.Context, auth *coreauth.Auth) {
	if h == nil {
		return
	}
	if h.next != nil {
		h.next.OnAuthRegistered(ctx, auth)
	}
}

// OnAuthUpdated 转发事件并触发运行时注册协调。
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

// OnResult 通过钩子链转发执行结果。
func (h *serviceCoreAuthHook) OnResult(ctx context.Context, result coreauth.Result) {
	if h == nil {
		return
	}
	if h.next != nil {
		h.next.OnResult(ctx, result)
	}
}

// attachCoreAuthHook 在 coreManager 上安装服务感知的钩子包装器。
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

// reconcileRuntimeAuthRegistration 保持服务运行时注册的同步。
func (s *Service) reconcileRuntimeAuthRegistration(auth *coreauth.Auth) {
	if s == nil || s.coreManager == nil || auth == nil || auth.ID == "" {
		return
	}
	if !coreauth.IsAuthActiveForRouting(auth) {
		// 当认证不可路由时，将其从全局模型注册表中注销。
		GlobalModelRegistry().UnregisterClient(auth.ID)
		s.coreManager.RefreshSchedulerEntry(auth.ID)
		return
	}
	// 当认证可路由时，恢复执行器/模型和调度器状态。
	s.ensureExecutorsForAuth(auth)
	s.registerModelsForAuth(auth)
	s.coreManager.ReconcileRegistryModelStates(context.Background(), auth.ID)
	s.coreManager.RefreshSchedulerEntry(auth.ID)
}
