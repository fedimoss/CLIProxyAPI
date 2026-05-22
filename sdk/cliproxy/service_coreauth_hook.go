package cliproxy

import (
	"context"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// serviceCoreAuthHook 灏嗘牳蹇冭璇佺敓鍛藉懆鏈熶簨浠朵腑缁у埌鏈嶅姟杩愯鏃跺悓姝ャ€?
type serviceCoreAuthHook struct {
	next    coreauth.Hook
	service *Service
}

// OnAuthRegistered 閫氳繃閽╁瓙閾捐浆鍙戞敞鍐屼簨浠躲€?
func (h *serviceCoreAuthHook) OnAuthRegistered(ctx context.Context, auth *coreauth.Auth) {
	if h == nil {
		return
	}
	if h.next != nil {
		h.next.OnAuthRegistered(ctx, auth)
	}
}

// OnAuthUpdated 杞彂浜嬩欢骞惰Е鍙戣繍琛屾椂娉ㄥ唽鍗忚皟銆?
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

// OnResult 閫氳繃閽╁瓙閾捐浆鍙戞墽琛岀粨鏋溿€?
func (h *serviceCoreAuthHook) OnResult(ctx context.Context, result coreauth.Result) {
	if h == nil {
		return
	}
	if h.next != nil {
		h.next.OnResult(ctx, result)
	}
}

// attachCoreAuthHook 鍦?coreManager 涓婂畨瑁呮湇鍔℃劅鐭ョ殑閽╁瓙鍖呰鍣ㄣ€?
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

// reconcileRuntimeAuthRegistration 淇濇寔鏈嶅姟杩愯鏃舵敞鍐岀殑鍚屾銆?
func (s *Service) reconcileRuntimeAuthRegistration(auth *coreauth.Auth) {
	if s == nil || s.coreManager == nil || auth == nil || auth.ID == "" {
		return
	}
	if !coreauth.IsAuthActiveForRouting(auth) {
		// 褰撹璇佷笉鍙矾鐢辨椂锛屽皢鍏朵粠鍏ㄥ眬妯″瀷娉ㄥ唽琛ㄤ腑娉ㄩ攢銆?
		GlobalModelRegistry().UnregisterClient(auth.ID)
		s.coreManager.RefreshSchedulerEntry(auth.ID)
		return
	}
	// 褰撹璇佸彲璺敱鏃讹紝鎭㈠鎵ц鍣?妯″瀷鍜岃皟搴﹀櫒鐘舵€併€?
	s.ensureExecutorsForAuth(auth)
	s.registerModelsForAuth(auth)
	s.coreManager.ReconcileRegistryModelStates(context.Background(), auth.ID)
	s.coreManager.RefreshSchedulerEntry(auth.ID)
}
