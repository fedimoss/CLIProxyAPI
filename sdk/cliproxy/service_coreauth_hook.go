package cliproxy

import (
	"context"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// serviceCoreAuthHook 把 core auth 管理器里的账号变更事件同步到 Service。
// 它本身不做鉴权，也不处理请求，只负责在账号状态变化后更新运行时注册信息。
type serviceCoreAuthHook struct {
	next    coreauth.Hook
	service *Service
}

// OnAuthRegistered 透传账号注册事件。
// 这里暂时不额外处理，只保留 hook 链能力，避免覆盖已有外部 hook。
func (h *serviceCoreAuthHook) OnAuthRegistered(ctx context.Context, auth *coreauth.Auth) {
	if h == nil {
		return
	}
	if h.next != nil {
		h.next.OnAuthRegistered(ctx, auth)
	}
}

// OnAuthUpdated 在账号被更新后同步 Service 侧的运行时注册状态。
// 比如账号被停用时从模型注册表移除，恢复正常时重新注册可用模型。
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

// OnResult 透传一次请求执行结果。
// 当前没有追加处理，保留是为了和 core auth 的 hook 接口保持完整一致。
func (h *serviceCoreAuthHook) OnResult(ctx context.Context, result coreauth.Result) {
	if h == nil {
		return
	}
	if h.next != nil {
		h.next.OnResult(ctx, result)
	}
}

// attachCoreAuthHook 把 Service 自己的 hook 挂到 coreManager 上。
// 这样 core auth 内部一旦有账号更新，Service 就能及时同步本地可用账号和调度信息。
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

// reconcileRuntimeAuthRegistration 根据账号当前状态，收敛 Service 侧的运行时注册结果。
// 非正常账号会被移出当前可用池；正常账号会补齐执行器、模型注册和调度器条目。
func (s *Service) reconcileRuntimeAuthRegistration(auth *coreauth.Auth) {
	if s == nil || s.coreManager == nil || auth == nil || auth.ID == "" {
		return
	}
	if coreauth.DBStatusForAuth(auth) != coreauth.DBStatusActive || auth.Disabled || auth.Status == coreauth.StatusDisabled {
		// 账号不再可用时，立刻从全局模型注册表移除，避免后续请求继续命中它。
		GlobalModelRegistry().UnregisterClient(auth.ID)
		s.coreManager.RefreshSchedulerEntry(auth.ID)
		return
	}
	// 账号恢复为可用后，重新补齐运行时依赖，并刷新调度器快照。
	s.ensureExecutorsForAuth(auth)
	s.registerModelsForAuth(auth)
	s.coreManager.RefreshSchedulerEntry(auth.ID)
}
