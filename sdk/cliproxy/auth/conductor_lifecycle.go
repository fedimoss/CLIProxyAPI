package auth

import (
	"context"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func NewManager(store Store, selector Selector, hook Hook) *Manager {
	if selector == nil {
		selector = &RoundRobinSelector{}
	}
	if hook == nil {
		hook = NoopHook{}
	}
	manager := &Manager{
		store:     store,
		executors: make(map[string]ProviderExecutor),
		selector:  selector,
		hook:      hook,
		auths:     make(map[string]*Auth),

		inactiveAuths:    make(map[string]*Auth),
		homeRuntimeAuths: make(map[string]map[string]*Auth),

		providerOffsets:  make(map[string]int),
		modelPoolOffsets: make(map[string]int),
		healthSemaphore: func() atomic.Value {
			v := atomic.Value{}
			v.Store(make(chan struct{}, healthProbeMaxWorkers))
			return v
		}(),
	}
	// atomic.Value 要求初始值非 nil。
	manager.runtimeConfig.Store(&internalconfig.Config{})
	manager.apiKeyModelAlias.Store(apiKeyModelAliasTable(nil))
	manager.scheduler = newAuthScheduler(selector)
	return manager
}

func isRuntimeActiveAuth(auth *Auth) bool {
	return IsAuthActiveForRouting(auth)
}

func (m *Manager) storeAuthLocked(auth *Auth) {
	if m == nil || auth == nil || strings.TrimSpace(auth.ID) == "" {
		return
	}
	if m.auths == nil {
		m.auths = make(map[string]*Auth)
	}
	if m.inactiveAuths == nil {
		m.inactiveAuths = make(map[string]*Auth)
	}
	delete(m.auths, auth.ID)
	delete(m.inactiveAuths, auth.ID)
	if isRuntimeActiveAuth(auth) {
		m.auths[auth.ID] = auth
		return
	}
	m.inactiveAuths[auth.ID] = auth
}

func (m *Manager) authByIDLocked(id string) (*Auth, bool) {
	if m == nil || id == "" {
		return nil, false
	}
	if auth, ok := m.auths[id]; ok && auth != nil {
		return auth, true
	}
	if auth, ok := m.inactiveAuths[id]; ok && auth != nil {
		return auth, true
	}
	return nil, false
}

func (m *Manager) SetHook(hook Hook) Hook {
	if m == nil {
		return nil
	}
	if hook == nil {
		hook = NoopHook{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := m.hook
	m.hook = hook
	return prev
}

func (m *Manager) Hook() Hook {
	if m == nil {
		return NoopHook{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.hook == nil {
		return NoopHook{}
	}
	return m.hook
}

// SetStore 替换底层持久化存储。
func (m *Manager) SetStore(store Store) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store = store
}

// SetRoundTripperProvider 注册一个返回每个认证的 RoundTripper 的提供器。
func (m *Manager) SetRoundTripperProvider(p RoundTripperProvider) {
	m.mu.Lock()
	m.rtProvider = p
	m.mu.Unlock()
}

// SetConfig 更新请求时辅助函数使用的运行时配置快照。
// 调用者应在重载时提供最新配置，以保持每个凭证的别名映射同步。
func (m *Manager) SetConfig(cfg *internalconfig.Config) {
	if m == nil {
		return
	}
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}
	m.runtimeConfig.Store(cfg)

	m.setHealthProbeWorkers(cfg.OAuthHealthProbeMaxWorkers())
	clearedCooldowns := m.clearDisabledCooldownStates(cfg)
	if !cfg.Home.Enabled {
		m.clearHomeRuntimeAuths()
	}

	m.rebuildAPIKeyModelAliasFromRuntimeConfig()
	if clearedCooldowns {
		m.persistCooldownStates(context.Background())
	}
}

// SetRetryConfig updates retry attempts, credential retry limit and cooldown wait interval.
func (m *Manager) SetRetryConfig(retry int, maxRetryInterval time.Duration, maxRetryCredentials int) {
	if m == nil {
		return
	}
	if retry < 0 {
		retry = 0
	}
	if maxRetryCredentials < 0 {
		maxRetryCredentials = 0
	}
	if maxRetryInterval < 0 {
		maxRetryInterval = 0
	}
	m.requestRetry.Store(int32(retry))
	m.maxRetryCredentials.Store(int32(maxRetryCredentials))
	m.maxRetryInterval.Store(maxRetryInterval.Nanoseconds())
}

// RegisterExecutor 向管理器注册一个提供商执行器。
func (m *Manager) RegisterExecutor(executor ProviderExecutor) {
	if executor == nil {
		return
	}
	provider := strings.TrimSpace(executor.Identifier())
	if provider == "" {
		return
	}

	var replaced ProviderExecutor
	m.mu.Lock()
	replaced = m.executors[provider]
	m.executors[provider] = executor
	m.mu.Unlock()

	if replaced == nil || replaced == executor {
		return
	}
	if closer, ok := replaced.(ExecutionSessionCloser); ok && closer != nil {
		closer.CloseExecutionSession(CloseAllExecutionSessionsID)
	}
}

// UnregisterExecutor 移除与提供商标识键关联的执行器。
func (m *Manager) UnregisterExecutor(provider string) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return
	}
	m.mu.Lock()
	delete(m.executors, provider)
	m.mu.Unlock()
}

// Register 向管理器插入新的认证条目。
func (m *Manager) Register(ctx context.Context, auth *Auth) (*Auth, error) {
	if auth == nil {
		return nil, nil
	}
	if auth.ID == "" {
		auth.ID = uuid.NewString()
	}
	auth.EnsureIndex()
	authClone := auth.Clone()
	m.mu.Lock()
	m.storeAuthLocked(authClone)
	m.mu.Unlock()
	m.rebuildAPIKeyModelAliasFromRuntimeConfig()
	if m.scheduler != nil {
		if isRuntimeActiveAuth(authClone) {
			m.scheduler.upsertAuth(authClone)
		} else {
			m.scheduler.removeAuth(authClone.ID)
		}
	}
	m.queueRefreshReschedule(auth.ID)
	_ = m.persist(ctx, auth)
	m.hook.OnAuthRegistered(ctx, auth.Clone())
	return auth.Clone(), nil
}

// Update replaces an existing auth entry and notifies hooks.
func (m *Manager) Update(ctx context.Context, auth *Auth) (*Auth, error) {
	if auth == nil || auth.ID == "" {
		return nil, nil
	}
	m.mu.Lock()
	existing, ok := m.authByIDLocked(auth.ID)
	if !ok || existing == nil {
		m.mu.Unlock()
		return nil, nil
	}
	if !auth.indexAssigned && auth.Index == "" {
		auth.Index = existing.Index
		auth.indexAssigned = existing.indexAssigned
	}
	auth.Success = existing.Success
	auth.Failed = existing.Failed
	auth.recentRequests = existing.recentRequests
	if !existing.Disabled && existing.Status != StatusDisabled && !auth.Disabled && auth.Status != StatusDisabled {
		if len(auth.ModelStates) == 0 && len(existing.ModelStates) > 0 {
			auth.ModelStates = existing.ModelStates
		}
	}
	auth.EnsureIndex()
	authClone := auth.Clone()
	m.storeAuthLocked(authClone)
	m.mu.Unlock()
	m.rebuildAPIKeyModelAliasFromRuntimeConfig()
	if m.scheduler != nil {
		if isRuntimeActiveAuth(authClone) {
			m.scheduler.upsertAuth(authClone)
		} else {
			m.scheduler.removeAuth(authClone.ID)
		}
	}
	m.queueRefreshReschedule(auth.ID)
	_ = m.persist(ctx, auth)
	m.hook.OnAuthUpdated(ctx, auth.Clone())
	return auth.Clone(), nil
}

// Load resets manager state from the backing store.
func (m *Manager) Load(ctx context.Context) error {
	m.mu.Lock()
	if m.store == nil {
		m.mu.Unlock()
		return nil
	}
	items, err := m.store.List(ctx)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	m.auths = make(map[string]*Auth, len(items))
	m.inactiveAuths = make(map[string]*Auth, len(items))
	for _, auth := range items {
		if auth == nil || auth.ID == "" {
			continue
		}
		auth.EnsureIndex()
		m.storeAuthLocked(auth.Clone())
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}
	m.rebuildAPIKeyModelAliasLocked(cfg)
	m.mu.Unlock()
	m.syncScheduler()
	return nil
}

// AvailableProviders returns the set of provider keys that currently have at least one
// registered auth record that is not disabled. It is a best-effort snapshot for routing
// decisions and does not account for per-model cooldowns or transient runtime availability.
// Disabled auths (Disabled flag or StatusDisabled) are excluded so routing does not target
// providers that auth selection would refuse to use, which would otherwise cause execution
// failures instead of falling back to lower-priority routers.
func (m *Manager) AvailableProviders() []string {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := make(map[string]struct{}, len(m.auths))
	out := make([]string, 0, len(m.auths))
	for _, auth := range m.auths {
		if auth == nil || auth.Disabled || auth.Status == StatusDisabled {
			continue
		}
		provider := strings.ToLower(strings.TrimSpace(auth.Provider))
		if provider == "" {
			continue
		}
		if _, ok := seen[provider]; ok {
			continue
		}
		seen[provider] = struct{}{}
		out = append(out, provider)
	}
	sort.Strings(out)
	return out
}

// HasProviderAuth reports whether at least one non-disabled auth record is registered for
// the provider. Disabled auths (Disabled flag or StatusDisabled) are excluded to match the
// behavior of auth selection, which refuses to pick disabled credentials.
func (m *Manager) HasProviderAuth(provider string) bool {
	if m == nil {
		return false
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, auth := range m.auths {
		if auth == nil || auth.Disabled || auth.Status == StatusDisabled {
			continue
		}
		if strings.ToLower(strings.TrimSpace(auth.Provider)) == provider {
			return true
		}
	}
	return false
}

func (m *Manager) List() []*Auth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*Auth, 0, len(m.auths))
	for _, auth := range m.auths {
		list = append(list, auth.Clone())
	}
	return list
}
func (m *Manager) ListAll() []*Auth {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Auth, 0, len(m.auths)+len(m.inactiveAuths))
	for _, auth := range m.auths {
		out = append(out, auth.Clone())
	}
	for _, auth := range m.inactiveAuths {
		out = append(out, auth.Clone())
	}
	return out
}

// GetByID 根据ID检索认证条目。

func (m *Manager) GetByID(id string) (*Auth, bool) {
	if id == "" {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	auth, ok := m.authByIDLocked(id)
	if !ok {
		return nil, false
	}
	return auth.Clone(), true
}

// GetExecutionSessionAuthByID retrieves a Home runtime auth scoped to an execution session.
func (m *Manager) GetExecutionSessionAuthByID(sessionID string, authID string) (*Auth, bool) {
	sessionID = strings.TrimSpace(sessionID)
	authID = strings.TrimSpace(authID)
	if m == nil || sessionID == "" || authID == "" {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	sessionAuths := m.homeRuntimeAuths[sessionID]
	auth := sessionAuths[authID]
	if auth == nil {
		return nil, false
	}
	return auth.Clone(), true
}

// Executor returns the registered provider executor for a provider key.

func (m *Manager) Executor(provider string) (ProviderExecutor, bool) {
	if m == nil {
		return nil, false
	}
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return nil, false
	}

	m.mu.RLock()
	executor, okExecutor := m.executors[provider]
	if !okExecutor {
		lowerProvider := strings.ToLower(provider)
		if lowerProvider != provider {
			executor, okExecutor = m.executors[lowerProvider]
		}
	}
	m.mu.RUnlock()

	if !okExecutor || executor == nil {
		return nil, false
	}
	return executor, true
}

// CloseExecutionSession 请求所有已注册的执行器释放指定的执行会话。
func (m *Manager) CloseExecutionSession(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if m == nil || sessionID == "" {
		return
	}

	m.mu.Lock()
	if sessionID == CloseAllExecutionSessionsID {
		m.clearHomeRuntimeAuthsLocked()
	} else {
		m.clearHomeRuntimeAuthsForSessionLocked(sessionID)
	}
	executors := make([]ProviderExecutor, 0, len(m.executors))
	for _, exec := range m.executors {
		executors = append(executors, exec)
	}
	m.mu.Unlock()

	for i := range executors {
		if closer, ok := executors[i].(ExecutionSessionCloser); ok && closer != nil {
			closer.CloseExecutionSession(sessionID)
		}
	}
}

func (m *Manager) persist(ctx context.Context, auth *Auth) error {
	if m.store == nil || auth == nil {
		return nil
	}
	if shouldSkipPersist(ctx) {
		return nil
	}
	if IsConfigAPIKeyAuth(auth) {
		return nil
	}
	if auth.Attributes != nil {
		if v := strings.ToLower(strings.TrimSpace(auth.Attributes["runtime_only"])); v == "true" {
			return nil
		}
	}
	// Skip persistence when metadata is absent (e.g., runtime-only auths).
	if auth.Metadata == nil {
		return nil
	}
	_, err := m.store.Save(ctx, auth)
	return err
}
