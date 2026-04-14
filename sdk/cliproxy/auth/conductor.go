package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

// ProviderExecutor defines the contract required by Manager to execute provider calls.
type ProviderExecutor interface {
	// Identifier returns the provider key handled by this executor.
	Identifier() string
	// Execute handles non-streaming execution and returns the provider response payload.
	Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error)
	// ExecuteStream handles streaming execution and returns a StreamResult containing
	// upstream headers and a channel of provider chunks.
	ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error)
	// Refresh attempts to refresh provider credentials and returns the updated auth state.
	Refresh(ctx context.Context, auth *Auth) (*Auth, error)
	// CountTokens returns the token count for the given request.
	CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error)
	// HttpRequest injects provider credentials into the supplied HTTP request and executes it.
	// Callers must close the response body when non-nil.
	HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error)
}

// ExecutionSessionCloser allows executors to release per-session runtime resources.
type ExecutionSessionCloser interface {
	CloseExecutionSession(sessionID string)
}

const (
	// CloseAllExecutionSessionsID asks an executor to release all active execution sessions.
	// Executors that do not support this marker may ignore it.
	CloseAllExecutionSessionsID = "__all_execution_sessions__"
)

// RefreshEvaluator allows runtime state to override refresh decisions.
type RefreshEvaluator interface {
	ShouldRefresh(now time.Time, auth *Auth) bool
}

const (
	refreshCheckInterval  = 5 * time.Second
	refreshMaxConcurrency = 16
	refreshPendingBackoff = time.Minute
	refreshFailureBackoff = 5 * time.Minute
	healthProbeTimeout    = 15 * time.Second
	healthProbeMaxGap     = 2 * time.Minute
	healthProbeMaxWorkers = internalconfig.DefaultOAuthHealthProbeMaxWorkers
	quotaBackoffBase      = time.Second
	quotaBackoffMax       = 30 * time.Minute

	// 鍛ㄩ搴﹀墿浣欐瘮渚嬩綆浜庤繖涓槇鍊兼椂锛屾祴娲讳細鎶婅处鍙锋爣璁颁负棰濆害涓嶈冻銆?
	healthProbeMinimumRemainingWeeklyPercent = 90
	// 鏈湴鍋ュ悍澶嶆娌跨敤 codex CLI 鐨?User-Agent锛屽敖閲忚创杩戠湡瀹炶姹傜幆澧冦€?
	codexHealthProbeUserAgent = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
	// 鍋ュ悍澶嶆鏀瑰啓璐﹀彿鐘舵€佸悗锛屽崟鐙粰钀藉簱棰勭暀涓€涓緝鐭秴鏃讹紝閬垮厤琚帰娴嬭姹傜殑瓒呮椂杩炲甫鍙栨秷銆?
	healthProbePersistTimeout = 5 * time.Second
)

var quotaCooldownDisabled atomic.Bool

// SetQuotaCooldownDisabled toggles quota cooldown scheduling globally.
func SetQuotaCooldownDisabled(disable bool) {
	quotaCooldownDisabled.Store(disable)
}

func quotaCooldownDisabledForAuth(auth *Auth) bool {
	if auth != nil {
		if override, ok := auth.DisableCoolingOverride(); ok {
			return override
		}
	}
	return quotaCooldownDisabled.Load()
}

// Result captures execution outcome used to adjust auth state.
type Result struct {
	// AuthID references the auth that produced this result.
	AuthID string
	// Provider is copied for convenience when emitting hooks.
	Provider string
	// Model is the upstream model identifier used for the request.
	Model string
	// Success marks whether the execution succeeded.
	Success bool
	// RetryAfter carries a provider supplied retry hint (e.g. 429 retryDelay).
	RetryAfter *time.Duration
	// Error describes the failure when Success is false.
	Error *Error
}

// Selector chooses an auth candidate for execution.
type Selector interface {
	Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error)
}

// Hook captures lifecycle callbacks for observing auth changes.
type Hook interface {
	// OnAuthRegistered fires when a new auth is registered.
	OnAuthRegistered(ctx context.Context, auth *Auth)
	// OnAuthUpdated fires when an existing auth changes state.
	OnAuthUpdated(ctx context.Context, auth *Auth)
	// OnResult fires when execution result is recorded.
	OnResult(ctx context.Context, result Result)
}

// NoopHook provides optional hook defaults.
type NoopHook struct{}

// OnAuthRegistered implements Hook.
func (NoopHook) OnAuthRegistered(context.Context, *Auth) {}

// OnAuthUpdated implements Hook.
func (NoopHook) OnAuthUpdated(context.Context, *Auth) {}

// OnResult implements Hook.
func (NoopHook) OnResult(context.Context, Result) {}

// Manager orchestrates auth lifecycle, selection, execution, and persistence.
type Manager struct {
	store     Store
	executors map[string]ProviderExecutor
	selector  Selector
	hook      Hook
	mu        sync.RWMutex
	auths     map[string]*Auth
	// inactiveAuths retains non-routable auth snapshots (for example DBStatus=2/3)
	// so status can still be queried and quota-limited auths can be rechecked later.
	inactiveAuths map[string]*Auth
	scheduler     *authScheduler
	// providerOffsets tracks per-model provider rotation state for multi-provider routing.
	providerOffsets map[string]int

	// Retry controls request retry behavior.
	requestRetry        atomic.Int32
	maxRetryCredentials atomic.Int32
	maxRetryInterval    atomic.Int64

	// oauthModelAlias stores global OAuth model alias mappings (alias -> upstream name) keyed by channel.
	oauthModelAlias atomic.Value

	// apiKeyModelAlias caches resolved model alias mappings for API-key auths.
	// Keyed by auth.ID, value is alias(lower) -> upstream model (including suffix).
	apiKeyModelAlias atomic.Value

	// modelPoolOffsets tracks per-auth alias pool rotation state.
	modelPoolOffsets map[string]int

	// runtimeConfig stores the latest application config for request-time decisions.
	// It is initialized in NewManager; never Load() before first Store().
	runtimeConfig atomic.Value

	// Optional HTTP RoundTripper provider injected by host.
	rtProvider RoundTripperProvider

	// Auto refresh state
	// Auto refresh state
	refreshCancel context.CancelFunc
	refreshLoop   *authAutoRefreshLoop
	// 本地健康复检状态
	healthSemaphore atomic.Value // 限制本地健康复检的全局并发数（最多 healthProbeMaxWorkers 个同时进行），存储 chan struct{}
	healthProbeAt   sync.Map     // 记录每个 auth 上一次复检时间，用于最小间隔控制（key: authID, value: time.Time）
	healthProbeBusy sync.Map     // 标记正在被复检的 auth，防止同一个 auth 同时跑多个探测（key: authID, value: struct{}）
}

// NewManager constructs a manager with optional custom selector and hook.
func NewManager(store Store, selector Selector, hook Hook) *Manager {
	if selector == nil {
		selector = &RoundRobinSelector{}
	}
	if hook == nil {
		hook = NoopHook{}
	}
	manager := &Manager{
		store:            store,
		executors:        make(map[string]ProviderExecutor),
		selector:         selector,
		hook:             hook,
		auths:            make(map[string]*Auth),
		inactiveAuths:    make(map[string]*Auth),
		providerOffsets:  make(map[string]int),
		modelPoolOffsets: make(map[string]int),
		healthSemaphore: func() atomic.Value {
			v := atomic.Value{}
			v.Store(make(chan struct{}, healthProbeMaxWorkers))
			return v
		}(),
	}
	// atomic.Value requires non-nil initial value.
	manager.runtimeConfig.Store(&internalconfig.Config{})
	manager.apiKeyModelAlias.Store(apiKeyModelAliasTable(nil))
	manager.scheduler = newAuthScheduler(selector)
	return manager
}

func isRuntimeActiveAuth(auth *Auth) bool {
	if auth == nil || strings.TrimSpace(auth.ID) == "" {
		return false
	}
	if NormalizeDBStatus(DBStatusForAuth(auth)) != DBStatusActive {
		return false
	}
	return !auth.Disabled && auth.Status != StatusDisabled
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

func isBuiltInSelector(selector Selector) bool {
	switch selector.(type) {
	case *RoundRobinSelector, *FillFirstSelector:
		return true
	default:
		return false
	}
}

func (m *Manager) syncSchedulerFromSnapshot(auths []*Auth) {
	if m == nil || m.scheduler == nil {
		return
	}
	m.scheduler.rebuild(auths)
}

func (m *Manager) syncScheduler() {
	if m == nil || m.scheduler == nil {
		return
	}
	m.syncSchedulerFromSnapshot(m.snapshotAuths())
}

func (m *Manager) snapshotAuths() []*Auth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Auth, 0, len(m.auths))
	for _, a := range m.auths {
		out = append(out, a.Clone())
	}
	return out
}

// RefreshSchedulerEntry re-upserts a single auth into the scheduler so that its
// supportedModelSet is rebuilt from the current global model registry state.
// This must be called after models have been registered for a newly added auth,
// because the initial scheduler.upsertAuth during Register/Update runs before
// registerModelsForAuth and therefore snapshots an empty model set.
func (m *Manager) RefreshSchedulerEntry(authID string) {
	if m == nil || m.scheduler == nil || authID == "" {
		return
	}
	m.mu.RLock()
	auth, ok := m.auths[authID]
	if !ok || auth == nil {
		m.mu.RUnlock()
		m.scheduler.removeAuth(authID)
		return
	}
	snapshot := auth.Clone()
	m.mu.RUnlock()
	m.scheduler.upsertAuth(snapshot)
}

// ReconcileRegistryModelStates aligns per-model runtime state with the current
// registry snapshot for one auth.
//
// Supported models are reset to a clean state because re-registration already
// cleared the registry-side cooldown/suspension snapshot. ModelStates for
// models that are no longer present in the registry are pruned entirely so
// renamed/removed models cannot keep auth-level status stale.
func (m *Manager) ReconcileRegistryModelStates(ctx context.Context, authID string) {
	if m == nil || authID == "" {
		return
	}

	supportedModels := registry.GetGlobalRegistry().GetModelsForClient(authID)
	supported := make(map[string]struct{}, len(supportedModels))
	for _, model := range supportedModels {
		if model == nil {
			continue
		}
		modelKey := canonicalModelKey(model.ID)
		if modelKey == "" {
			continue
		}
		supported[modelKey] = struct{}{}
	}

	var snapshot *Auth
	now := time.Now()

	m.mu.Lock()
	auth, ok := m.auths[authID]
	if ok && auth != nil && len(auth.ModelStates) > 0 {
		changed := false
		for modelKey, state := range auth.ModelStates {
			baseModel := canonicalModelKey(modelKey)
			if baseModel == "" {
				baseModel = strings.TrimSpace(modelKey)
			}
			if _, supportedModel := supported[baseModel]; !supportedModel {
				// Drop state for models that disappeared from the current registry
				// snapshot. Keeping them around leaks stale errors into auth-level
				// status, management output, and websocket fallback checks.
				delete(auth.ModelStates, modelKey)
				changed = true
				continue
			}
			if state == nil {
				continue
			}
			if modelStateIsClean(state) {
				continue
			}
			resetModelState(state, now)
			changed = true
		}
		if len(auth.ModelStates) == 0 {
			auth.ModelStates = nil
		}
		if changed {
			updateAggregatedAvailability(auth, now)
			if !hasModelError(auth, now) {
				auth.LastError = nil
				auth.StatusMessage = ""
				auth.Status = StatusActive
			}
			auth.UpdatedAt = now
			if errPersist := m.persist(ctx, auth); errPersist != nil {
				logEntryWithRequestID(ctx).WithField("auth_id", auth.ID).Warnf("failed to persist auth changes during model state reconciliation: %v", errPersist)
			}
			snapshot = auth.Clone()
		}
	}
	m.mu.Unlock()

	if m.scheduler != nil && snapshot != nil {
		m.scheduler.upsertAuth(snapshot)
	}
}

func (m *Manager) SetSelector(selector Selector) {
	if m == nil {
		return
	}
	if selector == nil {
		selector = &RoundRobinSelector{}
	}
	m.mu.Lock()
	m.selector = selector
	m.mu.Unlock()
	if m.scheduler != nil {
		m.scheduler.setSelector(selector)
		m.syncScheduler()
	}
}

// SetStore swaps the underlying persistence store.
func (m *Manager) SetStore(store Store) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store = store
}

// SetRoundTripperProvider register a provider that returns a per-auth RoundTripper.
func (m *Manager) SetRoundTripperProvider(p RoundTripperProvider) {
	m.mu.Lock()
	m.rtProvider = p
	m.mu.Unlock()
}

// SetConfig updates the runtime config snapshot used by request-time helpers.
// Callers should provide the latest config on reload so per-credential alias mapping stays in sync.
func (m *Manager) SetConfig(cfg *internalconfig.Config) {
	if m == nil {
		return
	}
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}
	m.runtimeConfig.Store(cfg)
	// 鏍规嵁鏈€鏂伴厤缃噸寤轰俊鍙烽噺锛屼娇骞跺彂涓婇檺绔嬪嵆鐢熸晥
	m.setHealthProbeWorkers(cfg.OAuthHealthProbeMaxWorkers())
	m.rebuildAPIKeyModelAliasFromRuntimeConfig()
}

// setHealthProbeWorkers 鏍规嵁 workers 閲嶅缓鍋ュ悍鎺㈡祴淇″彿閲忥紝鎺у埗骞跺彂鎺㈡祴涓婇檺銆?
// 浼犲叆鍊?鈮?0 鏃跺洖閫€鍒伴粯璁ゅ€笺€傞€氳繃 atomic.Value.Store 鍘熷瓙鍐欏叆锛屼繚璇佷笌鎺㈡祴璺緞鏃犵珵浜夈€?
func (m *Manager) setHealthProbeWorkers(workers int) {
	if m == nil {
		return
	}
	if workers <= 0 {
		workers = internalconfig.DefaultOAuthHealthProbeMaxWorkers
	}
	m.healthSemaphore.Store(make(chan struct{}, workers))
}

func (m *Manager) oauthHealthProbeMinRemainingWeeklyPercent() int {
	if m == nil {
		return internalconfig.DefaultOAuthHealthProbeMinRemainingWeeklyPercent
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return internalconfig.DefaultOAuthHealthProbeMinRemainingWeeklyPercent
	}
	return cfg.OAuthHealthProbeMinRemainingWeeklyPercent()
}

func (m *Manager) lookupAPIKeyUpstreamModel(authID, requestedModel string) string {
	if m == nil {
		return ""
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return ""
	}
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return ""
	}
	table, _ := m.apiKeyModelAlias.Load().(apiKeyModelAliasTable)
	if table == nil {
		return ""
	}
	byAlias := table[authID]
	if len(byAlias) == 0 {
		return ""
	}
	key := strings.ToLower(thinking.ParseSuffix(requestedModel).ModelName)
	if key == "" {
		key = strings.ToLower(requestedModel)
	}
	resolved := strings.TrimSpace(byAlias[key])
	if resolved == "" {
		return ""
	}
	return preserveRequestedModelSuffix(requestedModel, resolved)
}

func isAPIKeyAuth(auth *Auth) bool {
	if auth == nil {
		return false
	}
	kind, _ := auth.AccountInfo()
	return strings.EqualFold(strings.TrimSpace(kind), "api_key")
}

func isOpenAICompatAPIKeyAuth(auth *Auth) bool {
	if !isAPIKeyAuth(auth) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(auth.Provider), "openai-compatibility") {
		return true
	}
	if auth.Attributes == nil {
		return false
	}
	return strings.TrimSpace(auth.Attributes["compat_name"]) != ""
}

func openAICompatProviderKey(auth *Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		if providerKey := strings.TrimSpace(auth.Attributes["provider_key"]); providerKey != "" {
			return strings.ToLower(providerKey)
		}
		if compatName := strings.TrimSpace(auth.Attributes["compat_name"]); compatName != "" {
			return strings.ToLower(compatName)
		}
	}
	return strings.ToLower(strings.TrimSpace(auth.Provider))
}

func openAICompatModelPoolKey(auth *Auth, requestedModel string) string {
	base := strings.TrimSpace(thinking.ParseSuffix(requestedModel).ModelName)
	if base == "" {
		base = strings.TrimSpace(requestedModel)
	}
	return strings.ToLower(strings.TrimSpace(auth.ID)) + "|" + openAICompatProviderKey(auth) + "|" + strings.ToLower(base)
}

func (m *Manager) nextModelPoolOffset(key string, size int) int {
	if m == nil || size <= 1 {
		return 0
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.modelPoolOffsets == nil {
		m.modelPoolOffsets = make(map[string]int)
	}
	offset := m.modelPoolOffsets[key]
	if offset >= 2_147_483_640 {
		offset = 0
	}
	m.modelPoolOffsets[key] = offset + 1
	if size <= 0 {
		return 0
	}
	return offset % size
}

func rotateStrings(values []string, offset int) []string {
	if len(values) <= 1 {
		return values
	}
	if offset <= 0 {
		out := make([]string, len(values))
		copy(out, values)
		return out
	}
	offset = offset % len(values)
	out := make([]string, 0, len(values))
	out = append(out, values[offset:]...)
	out = append(out, values[:offset]...)
	return out
}

func (m *Manager) resolveOpenAICompatUpstreamModelPool(auth *Auth, requestedModel string) []string {
	if m == nil || !isOpenAICompatAPIKeyAuth(auth) {
		return nil
	}
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return nil
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}
	providerKey := ""
	compatName := ""
	if auth.Attributes != nil {
		providerKey = strings.TrimSpace(auth.Attributes["provider_key"])
		compatName = strings.TrimSpace(auth.Attributes["compat_name"])
	}
	entry := resolveOpenAICompatConfig(cfg, providerKey, compatName, auth.Provider)
	if entry == nil {
		return nil
	}
	return resolveModelAliasPoolFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
}

func preserveRequestedModelSuffix(requestedModel, resolved string) string {
	return preserveResolvedModelSuffix(resolved, thinking.ParseSuffix(requestedModel))
}

func (m *Manager) executionModelCandidates(auth *Auth, routeModel string) []string {
	requestedModel := rewriteModelForAuth(routeModel, auth)
	requestedModel = m.applyOAuthModelAlias(auth, requestedModel)
	if pool := m.resolveOpenAICompatUpstreamModelPool(auth, requestedModel); len(pool) > 0 {
		if len(pool) == 1 {
			return pool
		}
		offset := m.nextModelPoolOffset(openAICompatModelPoolKey(auth, requestedModel), len(pool))
		return rotateStrings(pool, offset)
	}
	resolved := m.applyAPIKeyModelAlias(auth, requestedModel)
	if strings.TrimSpace(resolved) == "" {
		resolved = requestedModel
	}
	return []string{resolved}
}

func (m *Manager) selectionModelForAuth(auth *Auth, routeModel string) string {
	requestedModel := rewriteModelForAuth(routeModel, auth)
	if strings.TrimSpace(requestedModel) == "" {
		requestedModel = strings.TrimSpace(routeModel)
	}
	resolvedModel := m.applyOAuthModelAlias(auth, requestedModel)
	if strings.TrimSpace(resolvedModel) == "" {
		resolvedModel = requestedModel
	}
	return resolvedModel
}

func (m *Manager) selectionModelKeyForAuth(auth *Auth, routeModel string) string {
	return canonicalModelKey(m.selectionModelForAuth(auth, routeModel))
}

func (m *Manager) stateModelForExecution(auth *Auth, routeModel, upstreamModel string, pooled bool) string {
	stateModel := executionResultModel(routeModel, upstreamModel, pooled)
	selectionModel := m.selectionModelForAuth(auth, routeModel)
	if canonicalModelKey(selectionModel) == canonicalModelKey(upstreamModel) && strings.TrimSpace(selectionModel) != "" {
		return strings.TrimSpace(upstreamModel)
	}
	return stateModel
}

func executionResultModel(routeModel, upstreamModel string, pooled bool) string {
	if pooled {
		if resolved := strings.TrimSpace(upstreamModel); resolved != "" {
			return resolved
		}
	}
	if requested := strings.TrimSpace(routeModel); requested != "" {
		return requested
	}
	return strings.TrimSpace(upstreamModel)
}

func (m *Manager) filterExecutionModels(auth *Auth, routeModel string, candidates []string, pooled bool) []string {
	if len(candidates) == 0 {
		return nil
	}
	now := time.Now()
	out := make([]string, 0, len(candidates))
	for _, upstreamModel := range candidates {
		stateModel := m.stateModelForExecution(auth, routeModel, upstreamModel, pooled)
		blocked, _, _ := isAuthBlockedForModel(auth, stateModel, now)
		if blocked {
			continue
		}
		out = append(out, upstreamModel)
	}
	return out
}

func (m *Manager) preparedExecutionModels(auth *Auth, routeModel string) ([]string, bool) {
	candidates := m.executionModelCandidates(auth, routeModel)
	pooled := len(candidates) > 1
	return m.filterExecutionModels(auth, routeModel, candidates, pooled), pooled
}

func (m *Manager) prepareExecutionModels(auth *Auth, routeModel string) []string {
	models, _ := m.preparedExecutionModels(auth, routeModel)
	return models
}

func (m *Manager) availableAuthsForRouteModel(auths []*Auth, provider, routeModel string, now time.Time) ([]*Auth, error) {
	if len(auths) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth candidates"}
	}

	availableByPriority := make(map[int][]*Auth)
	cooldownCount := 0
	var earliest time.Time
	for _, candidate := range auths {
		checkModel := m.selectionModelForAuth(candidate, routeModel)
		blocked, reason, next := isAuthBlockedForModel(candidate, checkModel, now)
		if !blocked {
			priority := authPriority(candidate)
			availableByPriority[priority] = append(availableByPriority[priority], candidate)
			continue
		}
		if reason == blockReasonCooldown {
			cooldownCount++
			if !next.IsZero() && (earliest.IsZero() || next.Before(earliest)) {
				earliest = next
			}
		}
	}

	if len(availableByPriority) == 0 {
		if cooldownCount == len(auths) && !earliest.IsZero() {
			providerForError := provider
			if providerForError == "mixed" {
				providerForError = ""
			}
			resetIn := earliest.Sub(now)
			if resetIn < 0 {
				resetIn = 0
			}
			return nil, newModelCooldownError(routeModel, providerForError, resetIn)
		}
		return nil, &Error{Code: "auth_unavailable", Message: "no auth available"}
	}

	bestPriority := 0
	found := false
	for priority := range availableByPriority {
		if !found || priority > bestPriority {
			bestPriority = priority
			found = true
		}
	}

	available := availableByPriority[bestPriority]
	if len(available) > 1 {
		sort.Slice(available, func(i, j int) bool { return available[i].ID < available[j].ID })
	}
	return available, nil
}

func selectionArgForSelector(selector Selector, routeModel string) string {
	if isBuiltInSelector(selector) {
		return ""
	}
	return routeModel
}

func (m *Manager) authSupportsRouteModel(registryRef *registry.ModelRegistry, auth *Auth, routeModel string) bool {
	if registryRef == nil || auth == nil {
		return true
	}
	routeKey := canonicalModelKey(routeModel)
	if routeKey == "" {
		return true
	}
	if registryRef.ClientSupportsModel(auth.ID, routeKey) {
		return true
	}
	selectionKey := m.selectionModelKeyForAuth(auth, routeModel)
	return selectionKey != "" && selectionKey != routeKey && registryRef.ClientSupportsModel(auth.ID, selectionKey)
}

func discardStreamChunks(ch <-chan cliproxyexecutor.StreamChunk) {
	if ch == nil {
		return
	}
	go func() {
		for range ch {
		}
	}()
}

type streamBootstrapError struct {
	cause   error
	headers http.Header
}

func cloneHTTPHeader(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	return headers.Clone()
}

func newStreamBootstrapError(err error, headers http.Header) error {
	if err == nil {
		return nil
	}
	return &streamBootstrapError{
		cause:   err,
		headers: cloneHTTPHeader(headers),
	}
}

func (e *streamBootstrapError) Error() string {
	if e == nil || e.cause == nil {
		return ""
	}
	return e.cause.Error()
}

func (e *streamBootstrapError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *streamBootstrapError) Headers() http.Header {
	if e == nil {
		return nil
	}
	return cloneHTTPHeader(e.headers)
}

func streamErrorResult(headers http.Header, err error) *cliproxyexecutor.StreamResult {
	ch := make(chan cliproxyexecutor.StreamChunk, 1)
	ch <- cliproxyexecutor.StreamChunk{Err: err}
	close(ch)
	return &cliproxyexecutor.StreamResult{
		Headers: cloneHTTPHeader(headers),
		Chunks:  ch,
	}
}

func readStreamBootstrap(ctx context.Context, ch <-chan cliproxyexecutor.StreamChunk) ([]cliproxyexecutor.StreamChunk, bool, error) {
	if ch == nil {
		return nil, true, nil
	}
	buffered := make([]cliproxyexecutor.StreamChunk, 0, 1)
	for {
		var (
			chunk cliproxyexecutor.StreamChunk
			ok    bool
		)
		if ctx != nil {
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case chunk, ok = <-ch:
			}
		} else {
			chunk, ok = <-ch
		}
		if !ok {
			return buffered, true, nil
		}
		if chunk.Err != nil {
			return nil, false, chunk.Err
		}
		buffered = append(buffered, chunk)
		if len(chunk.Payload) > 0 {
			return buffered, false, nil
		}
	}
}

func (m *Manager) wrapStreamResult(ctx context.Context, auth *Auth, provider, resultModel string, headers http.Header, buffered []cliproxyexecutor.StreamChunk, remaining <-chan cliproxyexecutor.StreamChunk) *cliproxyexecutor.StreamResult {
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		var failed bool
		forward := true
		emit := func(chunk cliproxyexecutor.StreamChunk) bool {
			if chunk.Err != nil && !failed {
				failed = true
				rerr := &Error{Message: chunk.Err.Error()}
				if se, ok := errors.AsType[cliproxyexecutor.StatusError](chunk.Err); ok && se != nil {
					rerr.HTTPStatus = se.StatusCode()
				}
				m.MarkResultLocal(ctx, Result{AuthID: auth.ID, Provider: provider, Model: resultModel, Success: false, Error: rerr})
			}
			if !forward {
				return false
			}
			if ctx == nil {
				out <- chunk
				return true
			}
			select {
			case <-ctx.Done():
				forward = false
				return false
			case out <- chunk:
				return true
			}
		}
		for _, chunk := range buffered {
			if ok := emit(chunk); !ok {
				discardStreamChunks(remaining)
				return
			}
		}
		for chunk := range remaining {
			if ok := emit(chunk); !ok {
				discardStreamChunks(remaining)
				return
			}
		}
		if !failed {
			m.MarkResultLocal(ctx, Result{AuthID: auth.ID, Provider: provider, Model: resultModel, Success: true})
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: headers, Chunks: out}
}

func (m *Manager) executeStreamWithModelPool(ctx context.Context, executor ProviderExecutor, auth *Auth, provider string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, routeModel string, execModels []string, pooled bool) (*cliproxyexecutor.StreamResult, error) {
	if executor == nil {
		return nil, &Error{Code: "executor_not_found", Message: "executor not registered"}
	}
	var lastErr error
	for idx, execModel := range execModels {
		resultModel := m.stateModelForExecution(auth, routeModel, execModel, pooled)
		execReq := req
		execReq.Model = execModel
		streamResult, errStream := executor.ExecuteStream(ctx, auth, execReq, opts)
		if errStream != nil {
			if errCtx := ctx.Err(); errCtx != nil {
				return nil, errCtx
			}
			rerr := &Error{Message: errStream.Error()}
			if se, ok := errors.AsType[cliproxyexecutor.StatusError](errStream); ok && se != nil {
				rerr.HTTPStatus = se.StatusCode()
			}
			result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, Success: false, Error: rerr}
			result.RetryAfter = retryAfterFromError(errStream)
			m.MarkResultLocal(ctx, result)
			if isRequestInvalidError(errStream) {
				return nil, errStream
			}
			lastErr = errStream
			continue
		}

		buffered, closed, bootstrapErr := readStreamBootstrap(ctx, streamResult.Chunks)
		if bootstrapErr != nil {
			if errCtx := ctx.Err(); errCtx != nil {
				discardStreamChunks(streamResult.Chunks)
				return nil, errCtx
			}
			if isRequestInvalidError(bootstrapErr) {
				rerr := &Error{Message: bootstrapErr.Error()}
				if se, ok := errors.AsType[cliproxyexecutor.StatusError](bootstrapErr); ok && se != nil {
					rerr.HTTPStatus = se.StatusCode()
				}
				result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, Success: false, Error: rerr}
				result.RetryAfter = retryAfterFromError(bootstrapErr)
				m.MarkResultLocal(ctx, result)
				discardStreamChunks(streamResult.Chunks)
				return nil, bootstrapErr
			}
			if idx < len(execModels)-1 {
				rerr := &Error{Message: bootstrapErr.Error()}
				if se, ok := errors.AsType[cliproxyexecutor.StatusError](bootstrapErr); ok && se != nil {
					rerr.HTTPStatus = se.StatusCode()
				}
				result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, Success: false, Error: rerr}
				result.RetryAfter = retryAfterFromError(bootstrapErr)
				m.MarkResultLocal(ctx, result)
				discardStreamChunks(streamResult.Chunks)
				lastErr = bootstrapErr
				continue
			}
			rerr := &Error{Message: bootstrapErr.Error()}
			if se, ok := errors.AsType[cliproxyexecutor.StatusError](bootstrapErr); ok && se != nil {
				rerr.HTTPStatus = se.StatusCode()
			}
			result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, Success: false, Error: rerr}
			result.RetryAfter = retryAfterFromError(bootstrapErr)
			m.MarkResultLocal(ctx, result)
			discardStreamChunks(streamResult.Chunks)
			return nil, newStreamBootstrapError(bootstrapErr, streamResult.Headers)
		}

		if closed && len(buffered) == 0 {
			emptyErr := &Error{Code: "empty_stream", Message: "upstream stream closed before first payload", Retryable: true}
			result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, Success: false, Error: emptyErr}
			m.MarkResultLocal(ctx, result)
			if idx < len(execModels)-1 {
				lastErr = emptyErr
				continue
			}
			return nil, newStreamBootstrapError(emptyErr, streamResult.Headers)
		}

		remaining := streamResult.Chunks
		if closed {
			closedCh := make(chan cliproxyexecutor.StreamChunk)
			close(closedCh)
			remaining = closedCh
		}
		return m.wrapStreamResult(ctx, auth.Clone(), provider, resultModel, streamResult.Headers, buffered, remaining), nil
	}
	if lastErr == nil {
		lastErr = &Error{Code: "auth_not_found", Message: "no upstream model available"}
	}
	return nil, lastErr
}

func (m *Manager) rebuildAPIKeyModelAliasFromRuntimeConfig() {
	if m == nil {
		return
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rebuildAPIKeyModelAliasLocked(cfg)
}

func (m *Manager) rebuildAPIKeyModelAliasLocked(cfg *internalconfig.Config) {
	if m == nil {
		return
	}
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}

	out := make(apiKeyModelAliasTable)
	for _, source := range []map[string]*Auth{m.auths, m.inactiveAuths} {
		for _, auth := range source {
			if auth == nil {
				continue
			}
			if strings.TrimSpace(auth.ID) == "" {
				continue
			}
			kind, _ := auth.AccountInfo()
			if !strings.EqualFold(strings.TrimSpace(kind), "api_key") {
				continue
			}

			byAlias := make(map[string]string)
			provider := strings.ToLower(strings.TrimSpace(auth.Provider))
			switch provider {
			case "gemini":
				if entry := resolveGeminiAPIKeyConfig(cfg, auth); entry != nil {
					compileAPIKeyModelAliasForModels(byAlias, entry.Models)
				}
			case "claude":
				if entry := resolveClaudeAPIKeyConfig(cfg, auth); entry != nil {
					compileAPIKeyModelAliasForModels(byAlias, entry.Models)
				}
			case "codex":
				if entry := resolveCodexAPIKeyConfig(cfg, auth); entry != nil {
					compileAPIKeyModelAliasForModels(byAlias, entry.Models)
				}
			case "vertex":
				if entry := resolveVertexAPIKeyConfig(cfg, auth); entry != nil {
					compileAPIKeyModelAliasForModels(byAlias, entry.Models)
				}
			default:
				// OpenAI-compat uses config selection from auth.Attributes.
				providerKey := ""
				compatName := ""
				if auth.Attributes != nil {
					providerKey = strings.TrimSpace(auth.Attributes["provider_key"])
					compatName = strings.TrimSpace(auth.Attributes["compat_name"])
				}
				if compatName != "" || strings.EqualFold(strings.TrimSpace(auth.Provider), "openai-compatibility") {
					if entry := resolveOpenAICompatConfig(cfg, providerKey, compatName, auth.Provider); entry != nil {
						compileAPIKeyModelAliasForModels(byAlias, entry.Models)
					}
				}
			}

			if len(byAlias) > 0 {
				out[auth.ID] = byAlias
			}
		}
	}

	m.apiKeyModelAlias.Store(out)
}

func compileAPIKeyModelAliasForModels[T interface {
	GetName() string
	GetAlias() string
}](out map[string]string, models []T) {
	if out == nil {
		return
	}
	for i := range models {
		alias := strings.TrimSpace(models[i].GetAlias())
		name := strings.TrimSpace(models[i].GetName())
		if alias == "" || name == "" {
			continue
		}
		aliasKey := strings.ToLower(thinking.ParseSuffix(alias).ModelName)
		if aliasKey == "" {
			aliasKey = strings.ToLower(alias)
		}
		// Config priority: first alias wins.
		if _, exists := out[aliasKey]; exists {
			continue
		}
		out[aliasKey] = name
		// Also allow direct lookup by upstream name (case-insensitive), so lookups on already-upstream
		// models remain a cheap no-op.
		nameKey := strings.ToLower(thinking.ParseSuffix(name).ModelName)
		if nameKey == "" {
			nameKey = strings.ToLower(name)
		}
		if nameKey != "" {
			if _, exists := out[nameKey]; !exists {
				out[nameKey] = name
			}
		}
		// Preserve config suffix priority by seeding a base-name lookup when name already has suffix.
		nameResult := thinking.ParseSuffix(name)
		if nameResult.HasSuffix {
			baseKey := strings.ToLower(strings.TrimSpace(nameResult.ModelName))
			if baseKey != "" {
				if _, exists := out[baseKey]; !exists {
					out[baseKey] = name
				}
			}
		}
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

// RegisterExecutor registers a provider executor with the manager.
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

// UnregisterExecutor removes the executor associated with the provider key.
func (m *Manager) UnregisterExecutor(provider string) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return
	}
	m.mu.Lock()
	delete(m.executors, provider)
	m.mu.Unlock()
}

// Register inserts a new auth entry into the manager.
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
	if existing, ok := m.authByIDLocked(auth.ID); ok && existing != nil {
		if !auth.indexAssigned && auth.Index == "" {
			auth.Index = existing.Index
			auth.indexAssigned = existing.indexAssigned
		}
		if !existing.Disabled && existing.Status != StatusDisabled && !auth.Disabled && auth.Status != StatusDisabled {
			if len(auth.ModelStates) == 0 && len(existing.ModelStates) > 0 {
				auth.ModelStates = existing.ModelStates
			}
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

// Execute performs a non-streaming execution using the configured selector and executor.
// It supports multiple providers for the same model and round-robins the starting provider per model.
func (m *Manager) Execute(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	normalized := m.normalizeProviders(providers)
	if len(normalized) == 0 {
		return cliproxyexecutor.Response{}, &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}

	_, maxRetryCredentials, maxWait := m.retrySettings()

	var lastErr error
	for attempt := 0; ; attempt++ {
		resp, errExec := m.executeMixedOnce(ctx, normalized, req, opts, maxRetryCredentials)
		if errExec == nil {
			return resp, nil
		}
		lastErr = errExec
		wait, shouldRetry := m.shouldRetryAfterError(errExec, attempt, normalized, req.Model, maxWait)
		if !shouldRetry {
			break
		}
		if errWait := waitForCooldown(ctx, wait); errWait != nil {
			return cliproxyexecutor.Response{}, errWait
		}
	}
	if lastErr != nil {
		return cliproxyexecutor.Response{}, lastErr
	}
	return cliproxyexecutor.Response{}, &Error{Code: "auth_not_found", Message: "no auth available"}
}

// ExecuteCount performs a non-streaming execution using the configured selector and executor.
// It supports multiple providers for the same model and round-robins the starting provider per model.
func (m *Manager) ExecuteCount(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	normalized := m.normalizeProviders(providers)
	if len(normalized) == 0 {
		return cliproxyexecutor.Response{}, &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}

	_, maxRetryCredentials, maxWait := m.retrySettings()

	var lastErr error
	for attempt := 0; ; attempt++ {
		resp, errExec := m.executeCountMixedOnce(ctx, normalized, req, opts, maxRetryCredentials)
		if errExec == nil {
			return resp, nil
		}
		lastErr = errExec
		wait, shouldRetry := m.shouldRetryAfterError(errExec, attempt, normalized, req.Model, maxWait)
		if !shouldRetry {
			break
		}
		if errWait := waitForCooldown(ctx, wait); errWait != nil {
			return cliproxyexecutor.Response{}, errWait
		}
	}
	if lastErr != nil {
		return cliproxyexecutor.Response{}, lastErr
	}
	return cliproxyexecutor.Response{}, &Error{Code: "auth_not_found", Message: "no auth available"}
}

// ExecuteStream performs a streaming execution using the configured selector and executor.
// It supports multiple providers for the same model and round-robins the starting provider per model.
func (m *Manager) ExecuteStream(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	normalized := m.normalizeProviders(providers)
	if len(normalized) == 0 {
		return nil, &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}

	_, maxRetryCredentials, maxWait := m.retrySettings()

	var lastErr error
	for attempt := 0; ; attempt++ {
		result, errStream := m.executeStreamMixedOnce(ctx, normalized, req, opts, maxRetryCredentials)
		if errStream == nil {
			return result, nil
		}
		lastErr = errStream
		wait, shouldRetry := m.shouldRetryAfterError(errStream, attempt, normalized, req.Model, maxWait)
		if !shouldRetry {
			break
		}
		if errWait := waitForCooldown(ctx, wait); errWait != nil {
			return nil, errWait
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
}

func (m *Manager) executeMixedOnce(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, maxRetryCredentials int) (cliproxyexecutor.Response, error) {
	if len(providers) == 0 {
		return cliproxyexecutor.Response{}, &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}
	routeModel := req.Model
	opts = ensureRequestedModelMetadata(opts, routeModel)
	tried := make(map[string]struct{})
	attempted := make(map[string]struct{})
	var lastErr error
	for {
		if maxRetryCredentials > 0 && len(attempted) >= maxRetryCredentials {
			if lastErr != nil {
				return cliproxyexecutor.Response{}, lastErr
			}
			return cliproxyexecutor.Response{}, &Error{Code: "auth_not_found", Message: "no auth available"}
		}
		auth, executor, provider, errPick := m.pickNextMixed(ctx, providers, routeModel, opts, tried)
		if errPick != nil {
			if lastErr != nil {
				return cliproxyexecutor.Response{}, lastErr
			}
			return cliproxyexecutor.Response{}, errPick
		}

		entry := logEntryWithRequestID(ctx)
		debugLogAuthSelection(entry, auth, provider, req.Model)
		publishSelectedAuthMetadata(opts.Metadata, auth.ID)

		tried[auth.ID] = struct{}{}
		execCtx := ctx
		if rt := m.roundTripperFor(auth); rt != nil {
			execCtx = context.WithValue(execCtx, roundTripperContextKey{}, rt)
			execCtx = context.WithValue(execCtx, "cliproxy.roundtripper", rt)
		}

		models, pooled := m.preparedExecutionModels(auth, routeModel)
		if len(models) == 0 {
			continue
		}
		attempted[auth.ID] = struct{}{}
		var authErr error
		for _, upstreamModel := range models {
			resultModel := m.stateModelForExecution(auth, routeModel, upstreamModel, pooled)
			execReq := req
			execReq.Model = upstreamModel
			resp, errExec := executor.Execute(execCtx, auth, execReq, opts)
			result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, Success: errExec == nil}
			if errExec != nil {
				if errCtx := execCtx.Err(); errCtx != nil {
					return cliproxyexecutor.Response{}, errCtx
				}
				result.Error = &Error{Message: errExec.Error()}
				if se, ok := errors.AsType[cliproxyexecutor.StatusError](errExec); ok && se != nil {
					result.Error.HTTPStatus = se.StatusCode()
				}
				if ra := retryAfterFromError(errExec); ra != nil {
					result.RetryAfter = ra
				}
				m.MarkResultLocal(execCtx, result)
				if isRequestInvalidError(errExec) {
					return cliproxyexecutor.Response{}, errExec
				}
				authErr = errExec
				continue
			}
			m.MarkResultLocal(execCtx, result)
			return resp, nil
		}
		if authErr != nil {
			if isRequestInvalidError(authErr) {
				return cliproxyexecutor.Response{}, authErr
			}
			lastErr = authErr
			continue
		}
	}
}

func (m *Manager) executeCountMixedOnce(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, maxRetryCredentials int) (cliproxyexecutor.Response, error) {
	if len(providers) == 0 {
		return cliproxyexecutor.Response{}, &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}
	routeModel := req.Model
	opts = ensureRequestedModelMetadata(opts, routeModel)
	tried := make(map[string]struct{})
	attempted := make(map[string]struct{})
	var lastErr error
	for {
		if maxRetryCredentials > 0 && len(attempted) >= maxRetryCredentials {
			if lastErr != nil {
				return cliproxyexecutor.Response{}, lastErr
			}
			return cliproxyexecutor.Response{}, &Error{Code: "auth_not_found", Message: "no auth available"}
		}
		auth, executor, provider, errPick := m.pickNextMixed(ctx, providers, routeModel, opts, tried)
		if errPick != nil {
			if lastErr != nil {
				return cliproxyexecutor.Response{}, lastErr
			}
			return cliproxyexecutor.Response{}, errPick
		}

		entry := logEntryWithRequestID(ctx)
		debugLogAuthSelection(entry, auth, provider, req.Model)
		publishSelectedAuthMetadata(opts.Metadata, auth.ID)

		tried[auth.ID] = struct{}{}
		execCtx := ctx
		if rt := m.roundTripperFor(auth); rt != nil {
			execCtx = context.WithValue(execCtx, roundTripperContextKey{}, rt)
			execCtx = context.WithValue(execCtx, "cliproxy.roundtripper", rt)
		}

		models, pooled := m.preparedExecutionModels(auth, routeModel)
		if len(models) == 0 {
			continue
		}
		attempted[auth.ID] = struct{}{}
		var authErr error
		for _, upstreamModel := range models {
			resultModel := m.stateModelForExecution(auth, routeModel, upstreamModel, pooled)
			execReq := req
			execReq.Model = upstreamModel
			resp, errExec := executor.CountTokens(execCtx, auth, execReq, opts)
			result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, Success: errExec == nil}
			if errExec != nil {
				if errCtx := execCtx.Err(); errCtx != nil {
					return cliproxyexecutor.Response{}, errCtx
				}
				result.Error = &Error{Message: errExec.Error()}
				if se, ok := errors.AsType[cliproxyexecutor.StatusError](errExec); ok && se != nil {
					result.Error.HTTPStatus = se.StatusCode()
				}
				if ra := retryAfterFromError(errExec); ra != nil {
					result.RetryAfter = ra
				}
				m.MarkResultLocal(execCtx, result)
				if isRequestInvalidError(errExec) {
					return cliproxyexecutor.Response{}, errExec
				}
				authErr = errExec
				continue
			}
			m.MarkResultLocal(execCtx, result)
			return resp, nil
		}
		if authErr != nil {
			if isRequestInvalidError(authErr) {
				return cliproxyexecutor.Response{}, authErr
			}
			lastErr = authErr
			continue
		}
	}
}

func (m *Manager) executeStreamMixedOnce(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, maxRetryCredentials int) (*cliproxyexecutor.StreamResult, error) {
	if len(providers) == 0 {
		return nil, &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}
	routeModel := req.Model
	opts = ensureRequestedModelMetadata(opts, routeModel)
	tried := make(map[string]struct{})
	attempted := make(map[string]struct{})
	var lastErr error
	for {
		if maxRetryCredentials > 0 && len(attempted) >= maxRetryCredentials {
			if lastErr != nil {
				var bootstrapErr *streamBootstrapError
				if errors.As(lastErr, &bootstrapErr) && bootstrapErr != nil {
					return streamErrorResult(bootstrapErr.Headers(), bootstrapErr.cause), nil
				}
				return nil, lastErr
			}
			return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
		}
		auth, executor, provider, errPick := m.pickNextMixed(ctx, providers, routeModel, opts, tried)
		if errPick != nil {
			if lastErr != nil {
				var bootstrapErr *streamBootstrapError
				if errors.As(lastErr, &bootstrapErr) && bootstrapErr != nil {
					return streamErrorResult(bootstrapErr.Headers(), bootstrapErr.cause), nil
				}
				return nil, lastErr
			}
			return nil, errPick
		}

		entry := logEntryWithRequestID(ctx)
		debugLogAuthSelection(entry, auth, provider, req.Model)
		publishSelectedAuthMetadata(opts.Metadata, auth.ID)

		tried[auth.ID] = struct{}{}
		execCtx := ctx
		if rt := m.roundTripperFor(auth); rt != nil {
			execCtx = context.WithValue(execCtx, roundTripperContextKey{}, rt)
			execCtx = context.WithValue(execCtx, "cliproxy.roundtripper", rt)
		}
		models, pooled := m.preparedExecutionModels(auth, routeModel)
		if len(models) == 0 {
			continue
		}
		attempted[auth.ID] = struct{}{}
		streamResult, errStream := m.executeStreamWithModelPool(execCtx, executor, auth, provider, req, opts, routeModel, models, pooled)
		if errStream != nil {
			if errCtx := execCtx.Err(); errCtx != nil {
				return nil, errCtx
			}
			if isRequestInvalidError(errStream) {
				return nil, errStream
			}
			lastErr = errStream
			continue
		}
		return streamResult, nil
	}
}

func ensureRequestedModelMetadata(opts cliproxyexecutor.Options, requestedModel string) cliproxyexecutor.Options {
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return opts
	}
	if hasRequestedModelMetadata(opts.Metadata) {
		return opts
	}
	if len(opts.Metadata) == 0 {
		opts.Metadata = map[string]any{cliproxyexecutor.RequestedModelMetadataKey: requestedModel}
		return opts
	}
	meta := make(map[string]any, len(opts.Metadata)+1)
	for k, v := range opts.Metadata {
		meta[k] = v
	}
	meta[cliproxyexecutor.RequestedModelMetadataKey] = requestedModel
	opts.Metadata = meta
	return opts
}

func hasRequestedModelMetadata(meta map[string]any) bool {
	if len(meta) == 0 {
		return false
	}
	raw, ok := meta[cliproxyexecutor.RequestedModelMetadataKey]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v) != ""
	case []byte:
		return strings.TrimSpace(string(v)) != ""
	default:
		return false
	}
}

func pinnedAuthIDFromMetadata(meta map[string]any) string {
	if len(meta) == 0 {
		return ""
	}
	raw, ok := meta[cliproxyexecutor.PinnedAuthMetadataKey]
	if !ok || raw == nil {
		return ""
	}
	switch val := raw.(type) {
	case string:
		return strings.TrimSpace(val)
	case []byte:
		return strings.TrimSpace(string(val))
	default:
		return ""
	}
}

func publishSelectedAuthMetadata(meta map[string]any, authID string) {
	if len(meta) == 0 {
		return
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	meta[cliproxyexecutor.SelectedAuthMetadataKey] = authID
	if callback, ok := meta[cliproxyexecutor.SelectedAuthCallbackMetadataKey].(func(string)); ok && callback != nil {
		callback(authID)
	}
}

func rewriteModelForAuth(model string, auth *Auth) string {
	if auth == nil || model == "" {
		return model
	}
	prefix := strings.TrimSpace(auth.Prefix)
	if prefix == "" {
		return model
	}
	needle := prefix + "/"
	if !strings.HasPrefix(model, needle) {
		return model
	}
	return strings.TrimPrefix(model, needle)
}

func (m *Manager) applyAPIKeyModelAlias(auth *Auth, requestedModel string) string {
	if m == nil || auth == nil {
		return requestedModel
	}

	kind, _ := auth.AccountInfo()
	if !strings.EqualFold(strings.TrimSpace(kind), "api_key") {
		return requestedModel
	}

	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return requestedModel
	}

	// Fast path: lookup per-auth mapping table (keyed by auth.ID).
	if resolved := m.lookupAPIKeyUpstreamModel(auth.ID, requestedModel); resolved != "" {
		return resolved
	}

	// Slow path: scan config for the matching credential entry and resolve alias.
	// This acts as a safety net if mappings are stale or auth.ID is missing.
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}

	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	upstreamModel := ""
	switch provider {
	case "gemini":
		upstreamModel = resolveUpstreamModelForGeminiAPIKey(cfg, auth, requestedModel)
	case "claude":
		upstreamModel = resolveUpstreamModelForClaudeAPIKey(cfg, auth, requestedModel)
	case "codex":
		upstreamModel = resolveUpstreamModelForCodexAPIKey(cfg, auth, requestedModel)
	case "vertex":
		upstreamModel = resolveUpstreamModelForVertexAPIKey(cfg, auth, requestedModel)
	default:
		upstreamModel = resolveUpstreamModelForOpenAICompatAPIKey(cfg, auth, requestedModel)
	}

	// Return upstream model if found, otherwise return requested model.
	if upstreamModel != "" {
		return upstreamModel
	}
	return requestedModel
}

// APIKeyConfigEntry is a generic interface for API key configurations.
type APIKeyConfigEntry interface {
	GetAPIKey() string
	GetBaseURL() string
}

func resolveAPIKeyConfig[T APIKeyConfigEntry](entries []T, auth *Auth) *T {
	if auth == nil || len(entries) == 0 {
		return nil
	}
	attrKey, attrBase := "", ""
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range entries {
		entry := &entries[i]
		cfgKey := strings.TrimSpace((*entry).GetAPIKey())
		cfgBase := strings.TrimSpace((*entry).GetBaseURL())
		if attrKey != "" && attrBase != "" {
			if strings.EqualFold(cfgKey, attrKey) && strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
			continue
		}
		if attrKey != "" && strings.EqualFold(cfgKey, attrKey) {
			if cfgBase == "" || strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
		}
		if attrKey == "" && attrBase != "" && strings.EqualFold(cfgBase, attrBase) {
			return entry
		}
	}
	if attrKey != "" {
		for i := range entries {
			entry := &entries[i]
			if strings.EqualFold(strings.TrimSpace((*entry).GetAPIKey()), attrKey) {
				return entry
			}
		}
	}
	return nil
}

func resolveGeminiAPIKeyConfig(cfg *internalconfig.Config, auth *Auth) *internalconfig.GeminiKey {
	if cfg == nil {
		return nil
	}
	return resolveAPIKeyConfig(cfg.GeminiKey, auth)
}

func resolveClaudeAPIKeyConfig(cfg *internalconfig.Config, auth *Auth) *internalconfig.ClaudeKey {
	if cfg == nil {
		return nil
	}
	return resolveAPIKeyConfig(cfg.ClaudeKey, auth)
}

func resolveCodexAPIKeyConfig(cfg *internalconfig.Config, auth *Auth) *internalconfig.CodexKey {
	if cfg == nil {
		return nil
	}
	return resolveAPIKeyConfig(cfg.CodexKey, auth)
}

func resolveVertexAPIKeyConfig(cfg *internalconfig.Config, auth *Auth) *internalconfig.VertexCompatKey {
	if cfg == nil {
		return nil
	}
	return resolveAPIKeyConfig(cfg.VertexCompatAPIKey, auth)
}

func resolveUpstreamModelForGeminiAPIKey(cfg *internalconfig.Config, auth *Auth, requestedModel string) string {
	entry := resolveGeminiAPIKeyConfig(cfg, auth)
	if entry == nil {
		return ""
	}
	return resolveModelAliasFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
}

func resolveUpstreamModelForClaudeAPIKey(cfg *internalconfig.Config, auth *Auth, requestedModel string) string {
	entry := resolveClaudeAPIKeyConfig(cfg, auth)
	if entry == nil {
		return ""
	}
	return resolveModelAliasFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
}

func resolveUpstreamModelForCodexAPIKey(cfg *internalconfig.Config, auth *Auth, requestedModel string) string {
	entry := resolveCodexAPIKeyConfig(cfg, auth)
	if entry == nil {
		return ""
	}
	return resolveModelAliasFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
}

func resolveUpstreamModelForVertexAPIKey(cfg *internalconfig.Config, auth *Auth, requestedModel string) string {
	entry := resolveVertexAPIKeyConfig(cfg, auth)
	if entry == nil {
		return ""
	}
	return resolveModelAliasFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
}

func resolveUpstreamModelForOpenAICompatAPIKey(cfg *internalconfig.Config, auth *Auth, requestedModel string) string {
	providerKey := ""
	compatName := ""
	if auth != nil && len(auth.Attributes) > 0 {
		providerKey = strings.TrimSpace(auth.Attributes["provider_key"])
		compatName = strings.TrimSpace(auth.Attributes["compat_name"])
	}
	if compatName == "" && !strings.EqualFold(strings.TrimSpace(auth.Provider), "openai-compatibility") {
		return ""
	}
	entry := resolveOpenAICompatConfig(cfg, providerKey, compatName, auth.Provider)
	if entry == nil {
		return ""
	}
	return resolveModelAliasFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
}

type apiKeyModelAliasTable map[string]map[string]string

func resolveOpenAICompatConfig(cfg *internalconfig.Config, providerKey, compatName, authProvider string) *internalconfig.OpenAICompatibility {
	if cfg == nil {
		return nil
	}
	candidates := make([]string, 0, 3)
	if v := strings.TrimSpace(compatName); v != "" {
		candidates = append(candidates, v)
	}
	if v := strings.TrimSpace(providerKey); v != "" {
		candidates = append(candidates, v)
	}
	if v := strings.TrimSpace(authProvider); v != "" {
		candidates = append(candidates, v)
	}
	for i := range cfg.OpenAICompatibility {
		compat := &cfg.OpenAICompatibility[i]
		for _, candidate := range candidates {
			if candidate != "" && strings.EqualFold(strings.TrimSpace(candidate), compat.Name) {
				return compat
			}
		}
	}
	return nil
}

func asModelAliasEntries[T interface {
	GetName() string
	GetAlias() string
}](models []T) []modelAliasEntry {
	if len(models) == 0 {
		return nil
	}
	out := make([]modelAliasEntry, 0, len(models))
	for i := range models {
		out = append(out, models[i])
	}
	return out
}

func (m *Manager) normalizeProviders(providers []string) []string {
	if len(providers) == 0 {
		return nil
	}
	result := make([]string, 0, len(providers))
	seen := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		p := strings.TrimSpace(strings.ToLower(provider))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		result = append(result, p)
	}
	return result
}

func (m *Manager) retrySettings() (int, int, time.Duration) {
	if m == nil {
		return 0, 0, 0
	}
	return int(m.requestRetry.Load()), int(m.maxRetryCredentials.Load()), time.Duration(m.maxRetryInterval.Load())
}

func (m *Manager) closestCooldownWait(providers []string, model string, attempt int) (time.Duration, bool) {
	if m == nil || len(providers) == 0 {
		return 0, false
	}
	now := time.Now()
	defaultRetry := int(m.requestRetry.Load())
	if defaultRetry < 0 {
		defaultRetry = 0
	}
	providerSet := make(map[string]struct{}, len(providers))
	for i := range providers {
		key := strings.TrimSpace(strings.ToLower(providers[i]))
		if key == "" {
			continue
		}
		providerSet[key] = struct{}{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var (
		found   bool
		minWait time.Duration
	)
	for _, auth := range m.auths {
		if auth == nil {
			continue
		}
		providerKey := strings.TrimSpace(strings.ToLower(auth.Provider))
		if _, ok := providerSet[providerKey]; !ok {
			continue
		}
		effectiveRetry := defaultRetry
		if override, ok := auth.RequestRetryOverride(); ok {
			effectiveRetry = override
		}
		if effectiveRetry < 0 {
			effectiveRetry = 0
		}
		if attempt >= effectiveRetry {
			continue
		}
		checkModel := model
		if strings.TrimSpace(model) != "" {
			checkModel = m.selectionModelForAuth(auth, model)
		}
		blocked, reason, next := isAuthBlockedForModel(auth, checkModel, now)
		if !blocked || next.IsZero() || reason == blockReasonDisabled {
			continue
		}
		wait := next.Sub(now)
		if wait < 0 {
			continue
		}
		if !found || wait < minWait {
			minWait = wait
			found = true
		}
	}
	return minWait, found
}

func (m *Manager) retryAllowed(attempt int, providers []string) bool {
	if m == nil || attempt < 0 || len(providers) == 0 {
		return false
	}
	defaultRetry := int(m.requestRetry.Load())
	if defaultRetry < 0 {
		defaultRetry = 0
	}
	providerSet := make(map[string]struct{}, len(providers))
	for i := range providers {
		key := strings.TrimSpace(strings.ToLower(providers[i]))
		if key == "" {
			continue
		}
		providerSet[key] = struct{}{}
	}
	if len(providerSet) == 0 {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, auth := range m.auths {
		if auth == nil {
			continue
		}
		providerKey := strings.TrimSpace(strings.ToLower(auth.Provider))
		if _, ok := providerSet[providerKey]; !ok {
			continue
		}
		effectiveRetry := defaultRetry
		if override, ok := auth.RequestRetryOverride(); ok {
			effectiveRetry = override
		}
		if effectiveRetry < 0 {
			effectiveRetry = 0
		}
		if attempt < effectiveRetry {
			return true
		}
	}
	return false
}

func (m *Manager) shouldRetryAfterError(err error, attempt int, providers []string, model string, maxWait time.Duration) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}
	if maxWait <= 0 {
		return 0, false
	}
	status := statusCodeFromError(err)
	if status == http.StatusOK {
		return 0, false
	}
	if isRequestInvalidError(err) {
		return 0, false
	}
	wait, found := m.closestCooldownWait(providers, model, attempt)
	if found {
		if wait > maxWait {
			return 0, false
		}
		return wait, true
	}
	if status != http.StatusTooManyRequests {
		return 0, false
	}
	if !m.retryAllowed(attempt, providers) {
		return 0, false
	}
	retryAfter := retryAfterFromError(err)
	if retryAfter == nil || *retryAfter <= 0 || *retryAfter > maxWait {
		return 0, false
	}
	return *retryAfter, true
}

func waitForCooldown(ctx context.Context, wait time.Duration) error {
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// MarkResult records an execution result and notifies hooks.
func (m *Manager) MarkResult(ctx context.Context, result Result) {
	if result.AuthID == "" {
		return
	}

	shouldResumeModel := false
	shouldSuspendModel := false
	shouldUnregisterClient := false
	suspendReason := ""
	clearModelQuota := false
	setModelQuota := false
	var authSnapshot *Auth

	m.mu.Lock()
	if auth, ok := m.authByIDLocked(result.AuthID); ok && auth != nil {
		now := time.Now()

		if result.Success {
			if result.Model != "" {
				state := ensureModelState(auth, result.Model)
				resetModelState(state, now)
				updateAggregatedAvailability(auth, now)
				if !hasModelError(auth, now) {
					auth.LastError = nil
					auth.StatusMessage = ""
					auth.Status = StatusActive
				}
				auth.UpdatedAt = now
				shouldResumeModel = true
				clearModelQuota = true
			} else {
				clearAuthStateOnSuccess(auth, now)
			}
		} else {
			// 璇锋眰澶辫触鍚庯紝鍏堝皾璇曞垽鏂繖娆″け璐ユ槸鍚﹀睘浜庘€滆繖涓?OAuth 宸茬粡姘镐箙澶辨晥鈥濈殑鎯呭喌銆?
			// 濡傛灉鍛戒腑杩欑鎯呭喌锛屽氨涓嶈鍐嶆妸瀹冨綋浣滀复鏃跺け璐ュ鐞嗭紝鑰屾槸鐩存帴璧拌嚜鍔ㄥ仠鐢ㄦ祦绋嬨€?
			if reason, okDisable := autoDisableReason(result.Error); okDisable {
				// 涓?Python 娴嬫椿鑴氭湰淇濇寔涓€鑷达細鍖哄垎鈥滈搴︿笉瓒斥€濆拰鈥滆处鍙峰け娲烩€濄€?
				// 鍏堢敤 extractCliproxyFailureReasonLocal 妫€鏌ラ敊璇唴瀹归噷鏄惁鍖呭惈棰濆害涓嶈冻淇″彿
				// (rate_limit銆乽sage_limit_reached銆乺emaining_percent 浣庝簬闃堝€肩瓑)銆?
				// 濡傛灉鍛戒腑棰濆害闂 鈫?DBStatus=3 (鍙妫€鎭㈠)锛屽惁鍒?鈫?DBStatus=2 (姘镐箙鍋滅敤)銆?
				failure := extractCliproxyFailureReasonLocal(result.Error.Message, m.oauthHealthProbeMinRemainingWeeklyPercent())
				if failure != nil && failure.QuotaLimited {
					// 鈹€鈹€ 棰濆害涓嶈冻锛氳处鍙疯繕娲荤潃锛屽彧鏄殏鏃朵笉鑳界敤 鈹€鈹€
					quotaReason := reason
					if failure.Reason != "" {
						quotaReason = failure.Reason
					}
					auth.DBStatus = DBStatusQuotaLimited
					auth.Disabled = false
					auth.Unavailable = true
					auth.Status = StatusError
					auth.StatusMessage = quotaReason
					auth.UpdatedAt = now
					auth.Quota = QuotaState{Exceeded: true, Reason: "quota"}
					auth.LastError = &Error{
						Code:       "quota_limited",
						Message:    quotaReason,
						HTTPStatus: result.Error.HTTPStatus,
					}
					if result.Model != "" {
						state := ensureModelState(auth, result.Model)
						state.Status = StatusError
						state.StatusMessage = quotaReason
						state.Unavailable = true
						state.UpdatedAt = now
					}
				} else {
					// 鈹€鈹€ 璐﹀彿澶辨椿锛氭案涔呭仠鐢?鈹€鈹€
					auth.DBStatus = DBStatusDisabled
					disableAuthForPermanentFailure(auth, result, reason, now)
				}
				// 绔嬪埢鍐欏洖鏁版嵁搴擄紝淇濊瘉鏈嶅姟閲嶅惎鍚庝粛鐒朵繚鎸佸搴旂姸鎬併€?
				_ = m.persist(ctx, auth)
				// 鍑嗗涓€浠芥渶鏂板揩鐓э紝鍚庨潰浜ょ粰璋冨害鍣ㄥ拰绠＄悊椤靛悓姝ユ樉绀恒€?
				authSnapshot = auth.Clone()
				// 鏍囪绋嶅悗鎾ゆ帀杩欎釜 auth 瀵瑰簲鐨勬ā鍨嬫敞鍐屻€?
				// 杩欐牱鍚庣画璇锋眰璺敱鏃讹紝灏变笉浼氬啀閫夊埌瀹冦€?
				shouldUnregisterClient = true
			} else if result.Model != "" {
				if !isRequestScopedNotFoundResultError(result.Error) {
					disableCooling := quotaCooldownDisabledForAuth(auth)
					state := ensureModelState(auth, result.Model)
					state.Unavailable = true
					state.Status = StatusError
					state.UpdatedAt = now
					if result.Error != nil {
						state.LastError = cloneError(result.Error)
						state.StatusMessage = result.Error.Message
						auth.LastError = cloneError(result.Error)
						auth.StatusMessage = result.Error.Message
					}

					statusCode := statusCodeFromResult(result.Error)
					if isModelSupportResultError(result.Error) {
						next := now.Add(12 * time.Hour)
						state.NextRetryAfter = next
						suspendReason = "model_not_supported"
						shouldSuspendModel = true
					} else {
						switch statusCode {
						case 401:
							if disableCooling {
								state.NextRetryAfter = time.Time{}
							} else {
								next := now.Add(30 * time.Minute)
								state.NextRetryAfter = next
								suspendReason = "unauthorized"
								shouldSuspendModel = true
							}
						case 402, 403:
							if disableCooling {
								state.NextRetryAfter = time.Time{}
							} else {
								next := now.Add(30 * time.Minute)
								state.NextRetryAfter = next
								suspendReason = "payment_required"
								shouldSuspendModel = true
							}
						case 404:
							if disableCooling {
								state.NextRetryAfter = time.Time{}
							} else {
								next := now.Add(12 * time.Hour)
								state.NextRetryAfter = next
								suspendReason = "not_found"
								shouldSuspendModel = true
							}
						case 429:
							var next time.Time
							backoffLevel := state.Quota.BackoffLevel
							if !disableCooling {
								if result.RetryAfter != nil {
									next = now.Add(*result.RetryAfter)
								} else {
									cooldown, nextLevel := nextQuotaCooldown(backoffLevel, disableCooling)
									if cooldown > 0 {
										next = now.Add(cooldown)
									}
									backoffLevel = nextLevel
								}
							}
							state.NextRetryAfter = next
							state.Quota = QuotaState{
								Exceeded:      true,
								Reason:        "quota",
								NextRecoverAt: next,
								BackoffLevel:  backoffLevel,
							}
							if !disableCooling {
								suspendReason = "quota"
								shouldSuspendModel = true
								setModelQuota = true
							}
						case 408, 500, 502, 503, 504:
							if disableCooling {
								state.NextRetryAfter = time.Time{}
							} else {
								next := now.Add(1 * time.Minute)
								state.NextRetryAfter = next
							}
						default:
							state.NextRetryAfter = time.Time{}
						}
					}

					auth.Status = StatusError
					auth.UpdatedAt = now
					updateAggregatedAvailability(auth, now)
				}
			} else {
				applyAuthFailureState(auth, result.Error, result.RetryAfter, now)
			}
		}

		m.storeAuthLocked(auth)
		if !shouldUnregisterClient {
			_ = m.persist(ctx, auth)
			authSnapshot = auth.Clone()
		}
	}
	m.mu.Unlock()
	if shouldUnregisterClient {
		// 杩欓噷鎵嶇湡姝ｆ妸杩欎釜 auth 瀵瑰簲鐨勬ā鍨嬩粠娉ㄥ唽琛ㄩ噷绉婚櫎銆?
		// 鍗充娇瀹冭繕淇濈暀鍦ㄥ唴瀛?auth 鍒楄〃涓紝涔熶笉浼氬啀鍙備笌鍚庣画璇锋眰璺敱銆?
		registry.GetGlobalRegistry().UnregisterClient(result.AuthID)
	}
	if m.scheduler != nil && authSnapshot != nil {
		m.scheduler.upsertAuth(authSnapshot)
	}

	if clearModelQuota && result.Model != "" {
		registry.GetGlobalRegistry().ClearModelQuotaExceeded(result.AuthID, result.Model)
	}
	if setModelQuota && result.Model != "" {
		registry.GetGlobalRegistry().SetModelQuotaExceeded(result.AuthID, result.Model)
	}
	if shouldResumeModel {
		registry.GetGlobalRegistry().ResumeClientModel(result.AuthID, result.Model)
	} else if shouldSuspendModel {
		registry.GetGlobalRegistry().SuspendClientModel(result.AuthID, result.Model, suspendReason)
	}

	m.hook.OnResult(ctx, result)
}

// MarkResultLocal 澶嶇敤鍘熸湁缁撴灉澶勭悊閫昏緫锛屽苟鍦ㄦ湰鍦扮増娴佺▼涓负鎴愬姛鐨?OAuth
// 璇锋眰琛ヤ笂涓€鏉″悗鍙板仴搴峰妫€閾捐矾銆?
func (m *Manager) MarkResultLocal(ctx context.Context, result Result) {
	m.MarkResult(ctx, result)
	if m == nil || !result.Success {
		return
	}
	// 鍙湁涓昏姹傚凡缁忔垚鍔熸椂锛屾墠鍦ㄥ悗鍙拌ˉ鍋氫竴娆♀€滈搴?鍋ュ悍鈥濆妫€銆?
	// 杩欐牱涓嶄細鎷栨參褰撳墠鍝嶅簲锛屼絾鑳藉敖蹇妸宸茬粡澶辨晥鐨?OAuth 娓呭嚭鍙敤姹犮€?
	m.scheduleAuthHealthProbeLocal(result.AuthID)
}

type authHealthProbeSpecLocal struct {
	Method  string
	URL     string
	Headers http.Header
}

type authHealthProbeFailureLocal struct {
	Reason       string
	QuotaLimited bool
}

// authHealthProbeDecisionLocal 琛ㄧず涓€娆℃祴娲诲悗鐨勬渶缁堣惤搴撶粨鏋溿€?
// DBStatus 浼氱洿鎺ュ奖鍝嶈处鍙锋槸鍚︾户缁疆璇€佹槸鍚︾户缁弬涓庡悗缁畾鏃跺妫€銆?
type authHealthProbeDecisionLocal struct {
	DBStatus   int
	HTTPStatus int
	Reason     string
}

// scheduleAuthHealthProbeLocal 寮傛瑙﹀彂鍗曚釜 auth 鐨勬湰鍦板仴搴峰妫€銆?
// 杩欓噷鏁呮剰涓嶉樆濉炲綋鍓嶈姹傦紝璁╁妫€缁撴灉鍙奖鍝嶅悗缁姹傘€?
func (m *Manager) scheduleAuthHealthProbeLocal(authID string) {
	authID = strings.TrimSpace(authID)
	if m == nil || authID == "" {
		return
	}
	go m.runAuthHealthProbeWithLimitLocal(context.Background(), authID)
}

// checkAuthHealthProbesLocal 鐢ㄤ簬瀹氭椂宸℃浠嶅彲琚妫€鐨?OAuth 璐﹀彿锛圖BStatus 涓?1 鎴?3锛夈€?
// 瀹冨拰鈥濇垚鍔熷悗寮傛澶嶆鈥濆叡鐢ㄥ悓涓€濂楀簳灞傛帰娴嬮€昏緫锛屽彧鏄Е鍙戞椂鏈轰笉鍚屻€?
func (m *Manager) checkAuthHealthProbesLocal(ctx context.Context) {
	if m == nil {
		return
	}
	auths := m.snapshotKnownAuths()
	pending := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		if !supportsAuthHealthProbeLocal(auth) {
			continue
		}
		pending = append(pending, auth)
	}
	if len(pending) > 0 {
		log.Infof("澶嶆寮€濮嬩簡")
	}
	for _, auth := range pending {
		go m.runAuthHealthProbeWithLimitLocal(ctx, auth.ID)
	}
}

// runAuthHealthProbeWithLimitLocal 璐熻矗缁欐湰鍦板仴搴峰妫€鍔犱袱灞備繚鎶わ細
// 1. 鍚屼竴涓?auth 鍚屼竴鏃堕棿鍙厑璁歌窇涓€涓妫€锛?
// 2. 鍏ㄥ眬骞跺彂鏁板彈闄愶紝閬垮厤涓€娆℃€ф墦澶鎺㈡祴璇锋眰銆?
func (m *Manager) runAuthHealthProbeWithLimitLocal(ctx context.Context, authID string) {
	authID = strings.TrimSpace(authID)
	if m == nil || authID == "" {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	auth, ok := m.beginAuthHealthProbeLocal(authID, time.Now())
	if !ok || auth == nil {
		return
	}
	defer m.endAuthHealthProbeLocal(authID)

	// 閫氳繃 atomic.Value.Load 鍘熷瓙璇诲彇淇″彿閲忥紝閬垮厤涓?setHealthProbeWorkers 鐨?Store 绔炵珵浜夈€?
	// 灏?channel 蹇収鍒板眬閮ㄥ彉閲忥紝纭繚 acquire/release 浣跨敤鍚屼竴瀹炰緥銆?
	sem, _ := m.healthSemaphore.Load().(chan struct{})
	if sem == nil {
		m.runAuthHealthProbeLocal(ctx, auth)
		return
	}
	select {
	case sem <- struct{}{}:
		// 閫氳繃鍙傛暟鎹曡幏 sem锛岀‘淇?release 鎿嶄綔涓?acquire 浣跨敤鍚屼竴 channel 瀹炰緥
		defer func(ch chan struct{}) { <-ch }(sem)
	case <-ctx.Done():
		return
	}
	m.runAuthHealthProbeLocal(ctx, auth)
}

// beginAuthHealthProbeLocal 鍒ゆ柇杩欐澶嶆鏄惁鍏佽寮€濮嬨€?
// 杩欓噷浼氬仛鏈€灏忛棿闅旀帶鍒讹紝閬垮厤鍚屼竴涓?auth 鍦ㄧ煭鏃堕棿鍐呰鍙嶅鎺㈡祴銆?
func (m *Manager) beginAuthHealthProbeLocal(authID string, now time.Time) (*Auth, bool) {
	if m == nil {
		return nil, false
	}
	if lastRun, ok := m.healthProbeAt.Load(authID); ok {
		if ts, okTime := lastRun.(time.Time); okTime && now.Sub(ts) < healthProbeMaxGap {
			return nil, false
		}
	}
	if _, loaded := m.healthProbeBusy.LoadOrStore(authID, struct{}{}); loaded {
		return nil, false
	}
	auth, ok := m.GetByID(authID)
	if !ok || !supportsAuthHealthProbeLocal(auth) {
		m.healthProbeBusy.Delete(authID)
		return nil, false
	}
	m.healthProbeAt.Store(authID, now)
	return auth, true
}

// endAuthHealthProbeLocal 鍦ㄥ妫€缁撴潫鍚庨噴鏀锯€滄鍦ㄥ妫€鈥濈殑鍗犱綅鏍囪銆?
func (m *Manager) endAuthHealthProbeLocal(authID string) {
	if m == nil {
		return
	}
	m.healthProbeBusy.Delete(strings.TrimSpace(authID))
}

// runAuthHealthProbeLocal 鐪熸鎵ц涓€娆″仴搴峰妫€銆?
// 鎺㈡祴缁撴灉閫氳繃 classifyAuthHealthProbeLocal 鍒嗙被涓轰笁鎬侊細
// 姝ｅ父锛圖BStatus=1锛夈€侀搴︿笉瓒筹紙DBStatus=3锛夈€佽处鍙峰け娲伙紙DBStatus=2锛夛紝
// 鍐嶉€氳繃 applyAuthHealthProbeDecisionLocal 鍐欏洖 auth 骞惰惤搴撱€?
func (m *Manager) runAuthHealthProbeLocal(parent context.Context, auth *Auth) {
	if m == nil || auth == nil {
		return
	}
	ctx := parent
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
	defer cancel()

	statusCode, body, errProbe := m.executeAuthHealthProbeLocal(ctx, auth)
	if errProbe != nil {
		log.WithError(errProbe).Debugf("auth health probe failed for %s (%s)", auth.Provider, auth.ID)
		decision := authHealthProbeDecisionLocal{
			DBStatus:   DBStatusDisabled,
			HTTPStatus: 0,
			Reason:     strings.TrimSpace(errProbe.Error()),
		}
		if shouldRetryAuthHealthProbeAfterErrorLocal(errProbe) {
			// 杩欑被 "Get \"https://chatgpt.com/backend-api/wham/usage\": context deadline exceeded"
			// 鏇村儚涓€娆′复鏃舵帰娴嬪け璐ワ紝涓嶅儚璐﹀彿宸茬粡褰诲簳澶辨椿銆?
			// 杩欓噷鏀硅惤鍒扮姸鎬?3锛岀瓑寰呬笅涓€娆″畾鏃跺妫€閲嶆柊鍒ゆ柇锛岃€屼笉鏄洿鎺ユ墦鎴愮姸鎬?2銆?
			decision.DBStatus = DBStatusQuotaLimited
			decision.HTTPStatus = http.StatusServiceUnavailable
			decision.Reason = healthProbeFailureReasonLocal(http.StatusServiceUnavailable, strings.TrimSpace(errProbe.Error()))
		}
		m.applyAuthHealthProbeDecisionLocal(ctx, auth.ID, decision)
		return
	}
	decision := m.classifyAuthHealthProbeLocal(statusCode, body)
	m.applyAuthHealthProbeDecisionLocal(ctx, auth.ID, decision)
}

// classifyAuthHealthProbeLocal 鏍规嵁娴嬫椿鍝嶅簲鐨?HTTP 鐘舵€佺爜鍜屽唴瀹癸紝鍒嗙被涓轰笁绉嶈惤搴撶粨鏋滐細
// 姝ｅ父锛圖BStatus=1锛夈€侀搴︿笉瓒筹紙DBStatus=3锛夈€佽处鍙峰け娲伙紙DBStatus=2锛夈€?
func (m *Manager) classifyAuthHealthProbeLocal(httpStatus int, body string) authHealthProbeDecisionLocal {
	// 鍒ゆ柇椤哄簭鍜屽閮ㄨ剼鏈繚鎸佷竴鑷达細
	// 鍏堢湅杩斿洖浣撻噷鐨?status_code锛屽啀鐪嬪け璐ヤ俊鍙凤紝鏈€鍚庡尯鍒嗗け娲昏繕鏄搴︿笉瓒炽€?
	httpStatus = normalizeAuthHealthProbeStatusCodeLocal(httpStatus, body)
	failure := extractCliproxyFailureReasonLocal(body, m.oauthHealthProbeMinRemainingWeeklyPercent())
	if httpStatus >= http.StatusBadRequest {
		// 鍙 status_code >= 400锛屽氨鍏堟妸杩欐娴嬫椿瑙嗕负澶辫触锛?
		// 鐒跺悗鍐嶆牴鎹?failure 鏄惁灞炰簬棰濆害绫婚棶棰橈紝鎶婄粨鏋滆惤鍒?2 鎴?3銆?
		reason := "HTTP " + strconv.Itoa(httpStatus)
		if failure != nil && strings.TrimSpace(failure.Reason) != "" {
			// 濡傛灉杩斿洖浣撻噷宸茬粡甯︿簡鏇村叿浣撶殑澶辫触鍘熷洜锛屼紭鍏堝睍绀哄畠锛屼笉淇濈暀绗肩粺鐨?HTTP 鏂囨銆?
			reason = strings.TrimSpace(failure.Reason)
		}
		if failure != nil && failure.QuotaLimited {
			return authHealthProbeDecisionLocal{
				DBStatus:   DBStatusQuotaLimited,
				HTTPStatus: normalizeQuotaHealthProbeStatusCodeLocal(httpStatus),
				Reason:     reason,
			}
		}
		if shouldRetryAuthHealthProbeResponseLocal(httpStatus, body) {
			// 褰撴祴娲绘帴鍙ｇ洿鎺ヨ繑鍥?
			// {"status":503,"detail":"Service Unavailable","message":"Get \"https://chatgpt.com/backend-api/wham/usage\": context deadline exceeded"}
			// 杩欑缁撴灉鏃讹紝涔熸寜鐘舵€?3 澶勭悊锛屼繚鐣欏埌涓嬩竴娆″妫€鍐嶇湅锛屼笉鍦ㄨ繖娆″氨鍒ゆ垚褰诲簳澶辨椿銆?
			return authHealthProbeDecisionLocal{
				DBStatus:   DBStatusQuotaLimited,
				HTTPStatus: httpStatus,
				Reason:     healthProbeFailureReasonLocal(httpStatus, body),
			}
		}
		return authHealthProbeDecisionLocal{
			DBStatus:   DBStatusDisabled,
			HTTPStatus: httpStatus,
			Reason:     reason,
		}
	}
	if failure != nil && strings.TrimSpace(failure.Reason) != "" {
		// status_code 鏈韩姝ｅ父鏃讹紝鍐嶇湅鍐呭閲屾湁娌℃湁鍧忎俊鍙锋垨棰濆害涓嶈冻淇″彿銆?
		status := DBStatusDisabled
		httpStatusForReason := httpStatus
		if failure.QuotaLimited {
			// 棰濆害闂涓嶆墦鎴愭鍙凤紝鑰屾槸钀藉埌鐘舵€?3锛岀瓑寰呭悗缁畾鏃跺妫€鎭㈠銆?
			status = DBStatusQuotaLimited
			httpStatusForReason = normalizeQuotaHealthProbeStatusCodeLocal(httpStatusForReason)
		}
		return authHealthProbeDecisionLocal{
			DBStatus:   status,
			HTTPStatus: httpStatusForReason,
			Reason:     strings.TrimSpace(failure.Reason),
		}
	}
	return authHealthProbeDecisionLocal{
		DBStatus:   DBStatusActive,
		HTTPStatus: httpStatus,
	}
}

// normalizeAuthHealthProbeStatusCodeLocal 浼樺厛鍙栧搷搴斾綋鍐呯殑 status_code锛屽洖閫€鍒?HTTP 鐘舵€佺爜銆?
func normalizeAuthHealthProbeStatusCodeLocal(httpStatus int, body string) int {
	// 濡傛灉鍝嶅簲浣撻噷宸茬粡甯︿簡 status_code锛屽氨浠ュ畠涓哄噯锛?
	// 杩欏拰澶栭儴鑴氭湰鐨勫垽鏂柟寮忎繚鎸佷竴鑷淬€?
	decoded := decodePossibleJSONPayloadLocal(body)
	if data, ok := decoded.(map[string]any); ok {
		if statusCode, okStatus := intValueFromAnyLocal(data["status_code"]); okStatus && statusCode > 0 {
			// 杩欓噷浼樺厛浣跨敤鍝嶅簲浣撻噷鐨?status_code锛岄伩鍏嶈澶栧眰 200 鎺╃洊鐪熷疄澶辫触銆?
			return statusCode
		}
	}
	if httpStatus > 0 {
		// 鍙湁鍝嶅簲浣撴病甯?status_code 鏃讹紝鎵嶅洖閫€鍒?HTTP 灞傜姸鎬佺爜銆?
		return httpStatus
	}
	return http.StatusOK
}

// normalizeQuotaHealthProbeStatusCodeLocal 棰濆害涓嶈冻鏃舵妸 0 鎴?200 缁熶竴褰掍竴鎴?429锛屼究浜庡悗缁睍绀哄拰鎺掓煡銆?
func normalizeQuotaHealthProbeStatusCodeLocal(status int) int {
	// 棰濆害涓嶈冻缁熶竴褰掍竴鎴?429锛屼究浜庡悗缁睍绀哄拰鎺掓煡銆?
	if status == 0 || status == http.StatusOK {
		return http.StatusTooManyRequests
	}
	return status
}

func shouldRetryAuthHealthProbeAfterErrorLocal(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		// 娴嬫椿璇锋眰鏈韩瓒呮椂锛岃鏄庤繖娆℃病鎺㈡祴鎴愬姛锛屽悗缁氦缁欎笅涓€娆″妫€銆?
		return true
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(err.Error())), "context deadline exceeded")
}

func shouldRetryAuthHealthProbeResponseLocal(httpStatus int, body string) bool {
	if httpStatus != http.StatusServiceUnavailable {
		return false
	}
	// 鍙 503 + deadline exceeded 杩欎竴绫讳复鏃朵笉鍙敤淇″彿鏀惧锛?
	// 璁╁畠杩涘叆鐘舵€?3锛岀瓑寰呬笅涓€娆″妫€锛涘叾浠?503 浠嶆寜鍘熸潵鐨勫け娲婚€昏緫澶勭悊銆?
	return containsDeadlineExceededSignalLocal(body)
}

func containsDeadlineExceededSignalLocal(payload any) bool {
	decoded := decodePossibleJSONPayloadLocal(payload)
	switch typed := decoded.(type) {
	case string:
		return strings.Contains(strings.ToLower(strings.TrimSpace(typed)), "context deadline exceeded")
	case map[string]any:
		for _, value := range typed {
			if containsDeadlineExceededSignalLocal(value) {
				return true
			}
		}
	case []any:
		for _, value := range typed {
			if containsDeadlineExceededSignalLocal(value) {
				return true
			}
		}
	}
	return false
}

func detachedPersistContextLocal(ctx context.Context) (context.Context, context.CancelFunc) {
	// 娴嬫椿璇锋眰鏈韩甯︽湁 15 绉掕秴鏃躲€?
	// 濡傛灉鎶婂悓涓€涓?ctx 缁х画浼犵粰钀藉簱锛屽墠闈㈢殑 HTTP 鎺㈡祴涓€鏃︽帴杩戣秴鏃讹紝
	// 鍚庨潰鐨?SELECT/UPDATE 杩樻病寮€濮嬪氨鍙兘鐩存帴鎷垮埌 context deadline exceeded銆?
	persistCtx, cancel := context.WithTimeout(context.Background(), healthProbePersistTimeout)
	if shouldSkipPersist(ctx) {
		persistCtx = WithSkipPersist(persistCtx)
	}
	return persistCtx, cancel
}

func (m *Manager) applyAuthHealthProbeDecisionLocal(ctx context.Context, authID string, decision authHealthProbeDecisionLocal) {
	authID = strings.TrimSpace(authID)
	if m == nil || authID == "" {
		return
	}
	now := time.Now()
	var (
		authSnapshot            *Auth
		shouldUnregisterClient  bool
		shouldNotifyAuthUpdated bool
	)

	m.mu.Lock()
	auth, ok := m.authByIDLocked(authID)
	if ok && auth != nil {
		prevDBStatus := DBStatusForAuth(auth)
		nextDBStatus := NormalizeDBStatus(decision.DBStatus)
		// 鍏堟妸鏈€鏂版祴娲荤粨璁哄啓鍥?auth锛屽悗闈㈢殑鎸佷箙鍖栧拰璋冨害閮戒互瀹冧负鍑嗐€?
		auth.DBStatus = nextDBStatus
		auth.UpdatedAt = now
		switch nextDBStatus {
		case DBStatusActive:
			// 鍙湁浠庣姸鎬?3 鎭㈠鍒扮姸鎬?1 鏃讹紝鎵嶆竻鐞嗛搴︿笉瓒崇暀涓嬬殑杩愯鏃剁棔杩广€?
			if prevDBStatus == DBStatusQuotaLimited {
				auth.Disabled = false
				auth.Status = StatusActive
				auth.Unavailable = false
				auth.StatusMessage = ""
				auth.LastError = nil
				auth.Quota = QuotaState{}
				auth.NextRetryAfter = time.Time{}
			}
		case DBStatusQuotaLimited:
			// 鐘舵€?3 琛ㄧず璐﹀彿杩樻椿鐫€锛屼絾棰濆害涓嶈冻锛屼笉鑳界户缁弬涓庤姹傝疆璇€?
			auth.Disabled = false
			auth.Status = StatusError
			auth.Unavailable = true
			// 杩欓噷淇濈暀鍘熷鍘熷洜锛屾柟渚垮悗缁帓鏌ュ埌搴曟槸鈥滈搴﹁€楀敖鈥濊繕鏄€滃墿浣欎綆浜?20%鈥濄€?
			auth.StatusMessage = strings.TrimSpace(decision.Reason)
			auth.LastError = &Error{
				Code:       "quota_limited",
				Message:    strings.TrimSpace(decision.Reason),
				HTTPStatus: normalizeQuotaHealthProbeStatusCodeLocal(decision.HTTPStatus),
			}
			auth.Quota = QuotaState{
				Exceeded: true,
				Reason:   "quota",
			}
			// 鐘舵€?3 涓嶄緷璧栧喎鍗存椂闂存仮澶嶏紝鑰屾槸渚濊禆涓嬩竴杞畾鏃跺妫€閲嶆柊鍒ゆ柇銆?
			auth.NextRetryAfter = time.Time{}
			shouldUnregisterClient = true
		case DBStatusDisabled:
			// 鐘舵€?2 琛ㄧず璐﹀彿澶辨椿锛屽悗缁笉鍐嶈嚜鍔ㄥ妫€銆?
			auth.Disabled = true
			auth.Unavailable = false
			auth.Status = StatusDisabled
			auth.StatusMessage = healthProbeFailureReasonLocal(decision.HTTPStatus, decision.Reason)
			auth.LastError = &Error{
				Code:       "account_deactivated",
				Message:    healthProbeFailureReasonLocal(decision.HTTPStatus, decision.Reason),
				HTTPStatus: decision.HTTPStatus,
			}
			auth.Quota = QuotaState{}
			auth.NextRetryAfter = time.Time{}
			// 鐘舵€?2 闇€瑕佺珛鍒讳粠娉ㄥ唽琛ㄤ腑绉婚櫎锛岄伩鍏嶅悗缁姹傜户缁懡涓繖鏉¤处鍙枫€?
			shouldUnregisterClient = true
		}
		// 姣忔娴嬫椿鍚庣殑鏈€鏂板垎绫婚兘绔嬪埢鍐欏簱锛岀‘淇濋噸鍚悗浠嶆寜鍚屼竴缁撴灉杩愯銆?
		// 杩欓噷鏁呮剰涓嶇敤娴嬫椿璇锋眰鑷繁鐨?ctx锛岄伩鍏嶄笂娓告帰娴嬪揩瓒呮椂鏃舵妸鏁版嵁搴撳啓鍏ヤ竴璧峰甫姝汇€?
		m.storeAuthLocked(auth)
		persistCtx, cancelPersist := detachedPersistContextLocal(ctx)
		_ = m.persist(persistCtx, auth)
		cancelPersist()
		authSnapshot = auth.Clone()
		shouldNotifyAuthUpdated = true
	}
	m.mu.Unlock()

	if shouldUnregisterClient {
		registry.GetGlobalRegistry().UnregisterClient(authID)
	}
	if m.scheduler != nil && authSnapshot != nil {
		if isRuntimeActiveAuth(authSnapshot) {
			m.scheduler.upsertAuth(authSnapshot)
		} else {
			m.scheduler.removeAuth(authSnapshot.ID)
		}
	}
	if shouldNotifyAuthUpdated && authSnapshot != nil {
		m.hook.OnAuthUpdated(ctx, authSnapshot)
	}
}

// executeAuthHealthProbeLocal 鍙戣捣涓€娆″疄闄呯殑鍋ュ悍鎺㈡祴璇锋眰銆?
// 杩欓噷澶嶇敤褰撳墠 auth 鑷繁鐨?HttpRequest 鑳藉姏锛屼繚璇佹帰娴嬫椂浣跨敤鐨?
// 鍑瘉銆佷唬鐞嗐€佽姹傚ご鍜屼富璇锋眰灏介噺涓€鑷淬€?
// 鍏蜂綋鈥滄帰娴嬪摢涓湴鍧€銆佺敤浠€涔堟柟娉曗€濈敱鎻愪緵鏂归€傞厤灞傚喅瀹氾紝
// 杩欐牱鍚庨潰鏂板鍏朵粬鎻愪緵鏂规椂锛屽彧闇€瑕佽ˉ鑷繁鐨?spec 鐢熸垚閫昏緫銆?
func (m *Manager) executeAuthHealthProbeLocal(ctx context.Context, auth *Auth) (int, string, error) {
	if m == nil || auth == nil {
		return 0, "", &Error{Code: "auth_not_found", Message: "auth is nil"}
	}
	spec, ok := authHealthProbeSpecForAuthLocal(auth)
	if !ok || spec == nil {
		return 0, "", &Error{Code: "not_supported", Message: "auth health probe is not supported"}
	}
	method := strings.TrimSpace(spec.Method)
	if method == "" {
		method = http.MethodGet
	}
	req, errReq := http.NewRequestWithContext(ctx, method, spec.URL, nil)
	if errReq != nil {
		return 0, "", errReq
	}
	if spec.Headers != nil {
		req.Header = spec.Headers.Clone()
	}
	if strings.TrimSpace(req.Header.Get("Accept")) == "" {
		req.Header.Set("Accept", "application/json")
	}
	resp, errDo := m.HttpRequest(ctx, auth, req)
	if errDo != nil {
		return 0, "", errDo
	}
	if resp == nil {
		return 0, "", &Error{Code: "probe_failed", Message: "health probe returned nil response"}
	}
	defer func() {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()
	body, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		return 0, "", errRead
	}
	return resp.StatusCode, strings.TrimSpace(string(body)), nil
}

// supportsAuthHealthProbeLocal 鍐冲畾鏌愪釜 auth 褰撳墠鏄惁鏀寔鏈湴鍋ュ悍澶嶆銆?
// 涓绘祦绋嬪彧渚濊禆杩欎釜缁熶竴鍏ュ彛锛屼笉鍏冲績鍏蜂綋鏄摢涓彁渚涙柟銆?
func supportsAuthHealthProbeLocal(auth *Auth) bool {
	if auth == nil {
		return false
	}
	// 鍙妫€鐘舵€?1 鍜?3锛?
	// 鐘舵€?2 宸茬粡鏄け娲昏处鍙凤紝涓嶅啀缁х画鎺㈡祴銆?
	switch DBStatusForAuth(auth) {
	case DBStatusDisabled:
		return false
	}
	if isAPIKeyAuth(auth) {
		// 杩欓噷鐨勬祴娲昏鍒欏彧閽堝 OAuth 璐﹀彿锛孉PI key 涓嶈蛋杩欐潯 wham/usage 澶嶆閾捐矾銆?
		return false
	}
	_, ok := authHealthProbeSpecForAuthLocal(auth)
	return ok
}

// authHealthProbeSpecForAuthLocal 鏄鎻愪緵鏂规墿灞曠偣銆?
// 褰撳墠妗嗘灦宸茬粡鏀寔鎸?provider 鍒嗘祦锛屼絾绗竴鐗堝彧鎸傛帴浜?codex銆?
// 鍚庨潰瑕佹柊澧炲叾浠栨彁渚涙柟鏃讹紝鍦ㄨ繖閲岃ˉ涓€涓垎鏀嵆鍙€?
func authHealthProbeSpecForAuthLocal(auth *Auth) (*authHealthProbeSpecLocal, bool) {
	if auth == nil {
		return nil, false
	}
	switch strings.ToLower(strings.TrimSpace(auth.Provider)) {
	case "codex":
		return codexAuthHealthProbeSpecLocal(auth)
	default:
		return nil, false
	}
}

// codexAuthHealthProbeSpecLocal 鐢熸垚 codex 鎻愪緵鏂逛娇鐢ㄧ殑鏈湴鍋ュ悍澶嶆 spec銆?
// 杩欓噷鍏堟妸 codex 鐨勬帰娴嬭鍒欑嫭绔嬪嚭鏉ワ紝鍚庣画鏂板鍏跺畠 provider 鏃跺彲浠ョ収杩欎釜缁撴瀯缁х画琛ャ€?
func codexAuthHealthProbeSpecLocal(auth *Auth) (*authHealthProbeSpecLocal, bool) {
	if auth == nil {
		return nil, false
	}
	baseURL := ""
	if auth.Attributes != nil {
		baseURL = strings.TrimSpace(auth.Attributes["base_url"])
	}
	if baseURL == "" {
		baseURL = "https://chatgpt.com/backend-api/codex"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if strings.HasSuffix(strings.ToLower(baseURL), "/codex") {
		baseURL = baseURL[:len(baseURL)-len("/codex")]
	}
	if baseURL == "" {
		return nil, false
	}
	headers := http.Header{
		"Accept":     {"application/json"},
		"User-Agent": {codexHealthProbeUserAgent},
	}
	// 灏介噺鎶婅处鍙锋爣璇嗕竴璧峰甫涓婏紝纭繚娴嬫椿鎵撳埌鐨勫氨鏄繖鏉¤处鍙疯嚜宸辩殑涓婁笅鏂囥€?
	if auth.Metadata != nil {
		if accountID, ok := auth.Metadata["account_id"].(string); ok {
			if trimmed := strings.TrimSpace(accountID); trimmed != "" {
				// 浼樺厛浣跨敤鐧诲綍鏃舵嬁鍒扮殑 account_id锛屼繚璇佹祴娲诲懡涓殑灏辨槸杩欐潯璐﹀彿鑷繁鐨?usage銆?
				headers.Set("Chatgpt-Account-Id", trimmed)
			}
		}
	}
	if len(headers.Values("Chatgpt-Account-Id")) == 0 && auth.Attributes != nil {
		if accountID := strings.TrimSpace(auth.Attributes["account_id"]); accountID != "" {
			// 鏌愪簺鏉ユ簮鍙兘鎶?account_id 鏀惧湪 Attributes锛岃繖閲屽仛涓€娆″厹搴曘€?
			headers.Set("Chatgpt-Account-Id", accountID)
		}
	}
	return &authHealthProbeSpecLocal{
		Method:  http.MethodGet,
		URL:     baseURL + "/wham/usage",
		Headers: headers,
	}, true
}

// decodePossibleJSONPayloadLocal 灏濊瘯鎶婂彲鑳芥槸 JSON 瀛楃涓茬殑 payload 鎷嗚В鎴愮粨鏋勫寲瀵硅薄銆?
// 鏈変簺瀛楁鏈韩鏄瓧绗︿覆浣嗛噷闈㈠張鍖呬簡涓€灞?JSON锛岀粺涓€鎷嗗紑鍚庯紝鍚庣画閫掑綊鎻愬彇澶辫触淇″彿
// 灏卞彲浠ユ寜鍚屼竴濂楃粨鏋勫鐞嗐€?
func decodePossibleJSONPayloadLocal(payload any) any {
	switch typed := payload.(type) {
	case nil:
		return nil
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return ""
		}
		var decoded any
		if json.Valid([]byte(trimmed)) && json.Unmarshal([]byte(trimmed), &decoded) == nil {
			// 鑳芥垚鍔熸媶鎴?JSON 鏃讹紝鍚庨潰灏卞彲浠ョ户缁€掑綊寰€閲屾寲澶辫触淇″彿銆?
			return decoded
		}
		return trimmed
	case []byte:
		return decodePossibleJSONPayloadLocal(string(typed))
	default:
		return payload
	}
}

// extractCliproxyFailureReasonLocal 浠庢祴娲诲搷搴斾腑閫掑綊鎻愬彇澶辫触鍘熷洜銆?
// 鎻愬彇椤哄簭涓庡閮ㄨ剼鏈繚鎸佷竴鑷达細error -> rate_limit/code_review_rate_limit -> additional_rate_limits -> 宓屽瀛楁 -> 鍏抽敭璇嶅厹搴曘€?
func extractCliproxyFailureReasonLocal(payload any, minRemainingWeeklyPercent int) *authHealthProbeFailureLocal {
	// 鎸夊閮ㄨ剼鏈殑椤哄簭鎻愬彇澶辫触鍘熷洜锛?
	// error -> rate_limit/code_review_rate_limit -> additional_rate_limits -> 宓屽瀛楁 -> 鍏抽敭璇嶅厹搴曘€?
	data := decodePossibleJSONPayloadLocal(payload)
	switch typed := data.(type) {
	case string:
		keyword, ok := knownCliproxyKeywordLocal(typed)
		if !ok {
			return nil
		}
		// 绾瓧绗︿覆鍦烘櫙鐩存帴鎸夊叧閿瘝鍖归厤锛屽拰澶栭儴鑴氭湰淇濇寔涓€鑷淬€?
		return &authHealthProbeFailureLocal{
			Reason:       formatKnownCliproxyErrorLocal(keyword),
			QuotaLimited: isCliproxyQuotaKeywordLocal(keyword),
		}
	case map[string]any:
		errorValue, _ := typed["error"].(map[string]any)
		if errorValue != nil {
			if errType, okType := stringValueFromAnyLocal(errorValue["type"]); okType && strings.TrimSpace(errType) != "" {
				// error.type 鏄渶寮轰俊鍙凤紝鍛戒腑鍚庣洿鎺ヨ繑鍥烇紝涓嶅啀缁х画寰€涓嬫壘銆?
				return &authHealthProbeFailureLocal{
					Reason:       formatKnownCliproxyErrorLocal(strings.TrimSpace(errType)),
					QuotaLimited: isCliproxyQuotaKeywordLocal(strings.TrimSpace(errType)),
				}
			}
			if errMessage, okMessage := stringValueFromAnyLocal(errorValue["message"]); okMessage && strings.TrimSpace(errMessage) != "" {
				keyword, foundKeyword := knownCliproxyKeywordLocal(errMessage)
				// error.message 娌℃湁缁撴瀯鍖栫被鍨嬫椂锛岃嚦灏戞妸鍘熸枃淇濈暀涓嬫潵锛屾柟渚垮悗缁畾浣嶃€?
				return &authHealthProbeFailureLocal{
					Reason:       strings.TrimSpace(errMessage),
					QuotaLimited: foundKeyword && isCliproxyQuotaKeywordLocal(keyword),
				}
			}
		}

		for _, key := range []string{"rate_limit", "code_review_rate_limit"} {
			minRemaining := 0
			if key == "rate_limit" {
				minRemaining = minRemainingWeeklyPercent
			}
			if failure := extractRateLimitReasonLocal(typed[key], key, minRemaining); failure != nil {
				return failure
			}
		}

		switch additional := typed["additional_rate_limits"].(type) {
		case []any:
			for idx, rateInfo := range additional {
				key := "additional_rate_limits[" + strconv.Itoa(idx) + "]"
				// 棰濆闄愰涔熸槸澶辨晥淇″彿鐨勪竴閮ㄥ垎锛岄€愰」閫掑綊妫€鏌ャ€?
				if failure := extractRateLimitReasonLocal(rateInfo, key, 0); failure != nil {
					return failure
				}
			}
		case map[string]any:
			for key, rateInfo := range additional {
				// 鏈変簺杩斿洖鏄璞″舰寮忥紝杩欓噷涔熻涓€骞惰鐩栨帀銆?
				if failure := extractRateLimitReasonLocal(rateInfo, "additional_rate_limits."+key, 0); failure != nil {
					return failure
				}
			}
		}

		for _, key := range []string{"data", "body", "response", "text", "content", "status_message"} {
			if failure := extractCliproxyFailureReasonLocal(typed[key], minRemainingWeeklyPercent); failure != nil {
				// 澶辫触淇℃伅鍙兘钘忓湪宓屽瀛楁閲岋紝杩欓噷閫掑綊鎸栧嚭鏉ャ€?
				return failure
			}
		}

		if encoded, errMarshal := json.Marshal(typed); errMarshal == nil {
			if keyword, okKeyword := knownCliproxyKeywordLocal(string(encoded)); okKeyword {
				// 鍓嶉潰閮芥病鍛戒腑鏃讹紝鍐嶅仛涓€娆″叏鏂囧叧閿瘝鍏滃簳銆?
				return &authHealthProbeFailureLocal{
					Reason:       formatKnownCliproxyErrorLocal(keyword),
					QuotaLimited: isCliproxyQuotaKeywordLocal(keyword),
				}
			}
		}
	}
	return nil
}

// extractRateLimitReasonLocal 浠?rate_limit 瀵硅薄涓彁鍙栭搴︿笉瓒崇殑鍏蜂綋鍘熷洜銆?
func extractRateLimitReasonLocal(rateInfo any, key string, minRemainingWeeklyPercent int) *authHealthProbeFailureLocal {
	// 棰濆害涓嶈冻鐨勫垽鏂垎涓ょ被锛?
	// 1. allowed=false 鎴?limit_reached=true
	// 2. 鍛ㄩ搴﹀墿浣欐瘮渚嬩綆浜庨槇鍊硷紙杩欓噷鍥哄畾涓?20%锛?
	data, ok := decodePossibleJSONPayloadLocal(rateInfo).(map[string]any)
	if !ok {
		return nil
	}
	allowed, hasAllowed := boolValueFromAnyLocal(data["allowed"])
	limitReached, hasLimitReached := boolValueFromAnyLocal(data["limit_reached"])
	if (hasAllowed && !allowed) || (hasLimitReached && limitReached) {
		// 涓€鏃︽槑纭彁绀轰笉鍏佽缁х画鐢紝鐩存帴瑙嗕负棰濆害涓嶈冻锛屼笉鍐嶅線涓嬬湅鐧惧垎姣斻€?
		label := key + " exhausted"
		switch key {
		case "rate_limit":
			label = "weekly quota exhausted"
		case "code_review_rate_limit":
			label = "code review weekly quota exhausted"
		}
		reason := label + " (allowed="
		if hasAllowed {
			reason += strconv.FormatBool(allowed)
		} else {
			reason += "unknown"
		}
		reason += ", limit_reached="
		if hasLimitReached {
			reason += strconv.FormatBool(limitReached)
		} else {
			reason += "unknown"
		}
		reason += ")"
		return &authHealthProbeFailureLocal{
			Reason:       reason,
			QuotaLimited: true,
		}
	}
	if key == "rate_limit" && minRemainingWeeklyPercent > 0 {
		if remainingPercent, okRemaining := extractRemainingPercentLocal(data["primary_window"]); okRemaining && remainingPercent < float64(minRemainingWeeklyPercent) {
			// 杩欓噷瀹炵幇浣犵殑鑷畾涔夎鍒欙細浣庝簬 20% 灏辫繘鍏ョ姸鎬?3銆?
			return &authHealthProbeFailureLocal{
				Reason:       "weekly quota remaining " + formatPercentLocal(remainingPercent) + "% is below " + strconv.Itoa(minRemainingWeeklyPercent) + "%",
				QuotaLimited: true,
			}
		}
	}
	return nil
}

// extractRemainingPercentLocal 浠?primary_window 涓彁鍙栧墿浣欓搴︾櫨鍒嗘瘮锛屽吋瀹?remaining_percent 鍜?used_percent 涓ょ鏍煎紡銆?
func extractRemainingPercentLocal(payload any) (float64, bool) {
	// 鍚屾椂鍏煎 remaining_percent 鍜?used_percent 涓ょ鏍煎紡銆?
	data, ok := decodePossibleJSONPayloadLocal(payload).(map[string]any)
	if !ok {
		return 0, false
	}
	if remainingPercent, okRemaining := floatValueFromAnyLocal(data["remaining_percent"]); okRemaining {
		// 鐩存帴缁欎簡 remaining_percent 鏃讹紝浼樺厛浣跨敤瀹冦€?
		return clampPercentLocal(remainingPercent), true
	}
	if usedPercent, okUsed := floatValueFromAnyLocal(data["used_percent"]); okUsed {
		// 鍙粰 used_percent 鏃讹紝鎹㈢畻鎴愬墿浣欑櫨鍒嗘瘮鍐嶅弬涓庡垽鏂€?
		return clampPercentLocal(100 - usedPercent), true
	}
	return 0, false
}

// clampPercentLocal 鎶婄櫨鍒嗘瘮鍊奸檺鍒跺湪 0-100 鑼冨洿鍐呫€?
func clampPercentLocal(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

// formatPercentLocal 鏍煎紡鍖栫櫨鍒嗘瘮涓哄彲璇诲瓧绗︿覆锛屽幓鎺夊熬閮ㄥ浣欑殑 0銆?
func formatPercentLocal(value float64) string {
	rounded := strconv.FormatFloat(value, 'f', 2, 64)
	rounded = strings.TrimRight(strings.TrimRight(rounded, "0"), ".")
	if rounded == "" {
		return "0"
	}
	return rounded
}

// knownCliproxyKeywordLocal 妫€鏌ュ瓧绗︿覆鏄惁鍖呭惈宸茬煡鐨勫け璐ュ叧閿瘝锛堝 usage_limit_reached銆乤ccount_deactivated 绛夛級銆?
func knownCliproxyKeywordLocal(value string) (string, bool) {
	value = strings.ToLower(value)
	for _, keyword := range []string{"usage_limit_reached", "account_deactivated", "insufficient_quota", "invalid_api_key", "unsupported_region"} {
		if strings.Contains(value, keyword) {
			return keyword, true
		}
	}
	return "", false
}

// isCliproxyQuotaKeywordLocal 鍒ゆ柇鍏抽敭璇嶆槸鍚﹀睘浜庨搴︾被闂锛坲sage_limit_reached銆乮nsufficient_quota锛夈€?
func isCliproxyQuotaKeywordLocal(keyword string) bool {
	switch strings.TrimSpace(keyword) {
	case "usage_limit_reached", "insufficient_quota":
		return true
	default:
		return false
	}
}

// formatKnownCliproxyErrorLocal 鎶婂凡鐭ラ敊璇叧閿瘝鏍煎紡鍖栦负鍙鐨勯敊璇弿杩帮紝渚夸簬鍐欏簱鍜屾帓鏌ャ€?
func formatKnownCliproxyErrorLocal(keyword string) string {
	// 缁欏父瑙侀敊璇被鍨嬭ˉ鍏呮洿濂借鐨勮鏄庯紝渚夸簬鍐欏簱鍜屾帓鏌ャ€?
	switch strings.TrimSpace(keyword) {
	case "usage_limit_reached":
		return "quota exhausted (usage_limit_reached)"
	case "account_deactivated":
		return "account deactivated (account_deactivated)"
	case "insufficient_quota":
		return "insufficient quota (insufficient_quota)"
	case "invalid_api_key":
		return "invalid API key (invalid_api_key)"
	case "unsupported_region":
		return "unsupported region (unsupported_region)"
	default:
		return "error type: " + strings.TrimSpace(keyword)
	}
}

// stringValueFromAnyLocal 浠庝换鎰忕被鍨嬪€间腑鎻愬彇瀛楃涓诧紙鏀寔 string銆乯son.Number锛夈€?
func stringValueFromAnyLocal(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case json.Number:
		return typed.String(), true
	}
	return "", false
}

// boolValueFromAnyLocal 浠庝换鎰忕被鍨嬪€间腑鎻愬彇甯冨皵鍊硷紙鏀寔 bool銆乻tring銆乯son.Number銆乫loat64锛夈€?
func boolValueFromAnyLocal(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		if err == nil {
			return parsed, true
		}
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			return parsed != 0, true
		}
	case float64:
		return typed != 0, true
	}
	return false, false
}

// floatValueFromAnyLocal 浠庝换鎰忕被鍨嬪€间腑鎻愬彇娴偣鏁帮紙鏀寔 float32/64銆乮nt銆乮nt64銆乯son.Number銆乻tring锛夈€?
func floatValueFromAnyLocal(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case json.Number:
		parsed, err := typed.Float64()
		if err == nil {
			return parsed, true
		}
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

// intValueFromAnyLocal 浠庝换鎰忕被鍨嬪€间腑鎻愬彇鏁存暟锛堟敮鎸?int銆乮nt32銆乮nt64銆乫loat64銆乯son.Number銆乻tring锛夈€?
func intValueFromAnyLocal(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			return int(parsed), true
		}
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

// healthProbeFailureReasonLocal 鎶婃祴娲诲け璐ョ殑鍘熷洜鏍煎紡鍖栦负 JSON 瀛楃涓诧紝渚涜惤搴撳拰灞曠ず銆?
// 濡傛灉鍝嶅簲浣撳凡缁忔槸鍚堟硶 JSON 鍒欏師鏍疯繑鍥烇紱鍚﹀垯鐢?status+detail+message 鍖呬竴灞?JSON 缁撴瀯銆?
func healthProbeFailureReasonLocal(status int, body string) string {
	body = strings.TrimSpace(body)
	if body != "" && json.Valid([]byte(body)) {
		return body
	}
	if status <= 0 {
		status = http.StatusServiceUnavailable
	}
	reason := struct {
		Status  int    `json:"status"`
		Detail  string `json:"detail,omitempty"`
		Message string `json:"message,omitempty"`
	}{
		Status: status,
		Detail: http.StatusText(status),
	}
	if body != "" {
		reason.Message = body
	}
	encoded, errMarshal := json.Marshal(reason)
	if errMarshal != nil {
		return `{"status":401}`
	}
	return string(encoded)
}

// unauthorizedHealthProbeReasonLocal 鐢熸垚 401 涓撶敤鐨勬祴娲诲け璐ュ師鍥犮€?
func unauthorizedHealthProbeReasonLocal(body string) string {
	return healthProbeFailureReasonLocal(http.StatusUnauthorized, body)
}

func ensureModelState(auth *Auth, model string) *ModelState {
	if auth == nil || model == "" {
		return nil
	}
	if auth.ModelStates == nil {
		auth.ModelStates = make(map[string]*ModelState)
	}
	if state, ok := auth.ModelStates[model]; ok && state != nil {
		return state
	}
	state := &ModelState{Status: StatusActive}
	auth.ModelStates[model] = state
	return state
}

func resetModelState(state *ModelState, now time.Time) {
	if state == nil {
		return
	}
	state.Unavailable = false
	state.Status = StatusActive
	state.StatusMessage = ""
	state.NextRetryAfter = time.Time{}
	state.LastError = nil
	state.Quota = QuotaState{}
	state.UpdatedAt = now
}

func modelStateIsClean(state *ModelState) bool {
	if state == nil {
		return true
	}
	if state.Status != StatusActive {
		return false
	}
	if state.Unavailable || state.StatusMessage != "" || !state.NextRetryAfter.IsZero() || state.LastError != nil {
		return false
	}
	if state.Quota.Exceeded || state.Quota.Reason != "" || !state.Quota.NextRecoverAt.IsZero() || state.Quota.BackoffLevel != 0 {
		return false
	}
	return true
}

func updateAggregatedAvailability(auth *Auth, now time.Time) {
	if auth == nil {
		return
	}
	if len(auth.ModelStates) == 0 {
		clearAggregatedAvailability(auth)
		return
	}
	allUnavailable := true
	earliestRetry := time.Time{}
	quotaExceeded := false
	quotaRecover := time.Time{}
	maxBackoffLevel := 0
	hasState := false
	for _, state := range auth.ModelStates {
		if state == nil {
			continue
		}
		hasState = true
		stateUnavailable := false
		if state.Status == StatusDisabled {
			stateUnavailable = true
		} else if state.Unavailable {
			if state.NextRetryAfter.IsZero() {
				stateUnavailable = false
			} else if state.NextRetryAfter.After(now) {
				stateUnavailable = true
				if earliestRetry.IsZero() || state.NextRetryAfter.Before(earliestRetry) {
					earliestRetry = state.NextRetryAfter
				}
			} else {
				state.Unavailable = false
				state.NextRetryAfter = time.Time{}
			}
		}
		if !stateUnavailable {
			allUnavailable = false
		}
		if state.Quota.Exceeded {
			quotaExceeded = true
			if quotaRecover.IsZero() || (!state.Quota.NextRecoverAt.IsZero() && state.Quota.NextRecoverAt.Before(quotaRecover)) {
				quotaRecover = state.Quota.NextRecoverAt
			}
			if state.Quota.BackoffLevel > maxBackoffLevel {
				maxBackoffLevel = state.Quota.BackoffLevel
			}
		}
	}
	if !hasState {
		clearAggregatedAvailability(auth)
		return
	}
	auth.Unavailable = allUnavailable
	if allUnavailable {
		auth.NextRetryAfter = earliestRetry
	} else {
		auth.NextRetryAfter = time.Time{}
	}
	if quotaExceeded {
		auth.Quota.Exceeded = true
		auth.Quota.Reason = "quota"
		auth.Quota.NextRecoverAt = quotaRecover
		auth.Quota.BackoffLevel = maxBackoffLevel
	} else {
		auth.Quota.Exceeded = false
		auth.Quota.Reason = ""
		auth.Quota.NextRecoverAt = time.Time{}
		auth.Quota.BackoffLevel = 0
	}
}

func clearAggregatedAvailability(auth *Auth) {
	if auth == nil {
		return
	}
	auth.Unavailable = false
	auth.NextRetryAfter = time.Time{}
	auth.Quota = QuotaState{}
}

func hasModelError(auth *Auth, now time.Time) bool {
	if auth == nil || len(auth.ModelStates) == 0 {
		return false
	}
	for _, state := range auth.ModelStates {
		if state == nil {
			continue
		}
		if state.LastError != nil {
			return true
		}
		if state.Status == StatusError {
			if state.Unavailable && (state.NextRetryAfter.IsZero() || state.NextRetryAfter.After(now)) {
				return true
			}
		}
	}
	return false
}

func clearAuthStateOnSuccess(auth *Auth, now time.Time) {
	if auth == nil {
		return
	}
	auth.Unavailable = false
	auth.Status = StatusActive
	auth.StatusMessage = ""
	auth.Quota.Exceeded = false
	auth.Quota.Reason = ""
	auth.Quota.NextRecoverAt = time.Time{}
	auth.Quota.BackoffLevel = 0
	auth.LastError = nil
	auth.NextRetryAfter = time.Time{}
	auth.UpdatedAt = now
}

func cloneError(err *Error) *Error {
	if err == nil {
		return nil
	}
	return &Error{
		Code:       err.Code,
		Message:    err.Message,
		Retryable:  err.Retryable,
		HTTPStatus: err.HTTPStatus,
	}
}

func statusCodeFromError(err error) int {
	if err == nil {
		return 0
	}
	type statusCoder interface {
		StatusCode() int
	}
	var sc statusCoder
	if errors.As(err, &sc) && sc != nil {
		return sc.StatusCode()
	}
	return 0
}

func retryAfterFromError(err error) *time.Duration {
	if err == nil {
		return nil
	}
	type retryAfterProvider interface {
		RetryAfter() *time.Duration
	}
	rap, ok := err.(retryAfterProvider)
	if !ok || rap == nil {
		return nil
	}
	retryAfter := rap.RetryAfter()
	if retryAfter == nil {
		return nil
	}
	return new(*retryAfter)
}

func statusCodeFromResult(err *Error) int {
	if err == nil {
		return 0
	}
	return err.StatusCode()
}

func isModelSupportErrorMessage(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	if lower == "" {
		return false
	}
	patterns := [...]string{
		"model_not_supported",
		"requested model is not supported",
		"requested model is unsupported",
		"requested model is unavailable",
		"model is not supported",
		"model not supported",
		"unsupported model",
		"model unavailable",
		"not available for your plan",
		"not available for your account",
	}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func isModelSupportError(err error) bool {
	if err == nil {
		return false
	}
	status := statusCodeFromError(err)
	if status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
		return false
	}
	return isModelSupportErrorMessage(err.Error())
}

func isModelSupportResultError(err *Error) bool {
	if err == nil {
		return false
	}
	status := statusCodeFromResult(err)
	if status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
		return false
	}
	return isModelSupportErrorMessage(err.Message)
}

func isRequestScopedNotFoundMessage(message string) bool {
	if message == "" {
		return false
	}
	lower := strings.ToLower(message)
	return strings.Contains(lower, "item with id") &&
		strings.Contains(lower, "not found") &&
		strings.Contains(lower, "items are not persisted when `store` is set to false")
}

func isRequestScopedNotFoundResultError(err *Error) bool {
	if err == nil || statusCodeFromResult(err) != http.StatusNotFound {
		return false
	}
	return isRequestScopedNotFoundMessage(err.Message)
}

// isRequestInvalidError returns true if the error represents a client request
// error that should not be retried. Specifically, it treats 400 responses with
// "invalid_request_error", request-scoped 404 item misses caused by `store=false`,
// and all 422 responses as request-shape failures, where switching auths or
// pooled upstream models will not help. Model-support errors are excluded so
// routing can fall through to another auth or upstream.
func isRequestInvalidError(err error) bool {
	if err == nil {
		return false
	}
	if isModelSupportError(err) {
		return false
	}
	status := statusCodeFromError(err)
	switch status {
	case http.StatusBadRequest:
		return strings.Contains(err.Error(), "invalid_request_error")
	case http.StatusNotFound:
		return isRequestScopedNotFoundMessage(err.Error())
	case http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

func applyAuthFailureState(auth *Auth, resultErr *Error, retryAfter *time.Duration, now time.Time) {
	if auth == nil {
		return
	}
	if isRequestScopedNotFoundResultError(resultErr) {
		return
	}
	disableCooling := quotaCooldownDisabledForAuth(auth)
	auth.Unavailable = true
	auth.Status = StatusError
	auth.UpdatedAt = now
	if resultErr != nil {
		auth.LastError = cloneError(resultErr)
		if resultErr.Message != "" {
			auth.StatusMessage = resultErr.Message
		}
	}
	statusCode := statusCodeFromResult(resultErr)
	switch statusCode {
	case 401:
		auth.StatusMessage = "unauthorized"
		if disableCooling {
			auth.NextRetryAfter = time.Time{}
		} else {
			auth.NextRetryAfter = now.Add(30 * time.Minute)
		}
	case 402, 403:
		auth.StatusMessage = "payment_required"
		if disableCooling {
			auth.NextRetryAfter = time.Time{}
		} else {
			auth.NextRetryAfter = now.Add(30 * time.Minute)
		}
	case 404:
		auth.StatusMessage = "not_found"
		if disableCooling {
			auth.NextRetryAfter = time.Time{}
		} else {
			auth.NextRetryAfter = now.Add(12 * time.Hour)
		}
	case 429:
		auth.StatusMessage = "quota exhausted"
		auth.Quota.Exceeded = true
		auth.Quota.Reason = "quota"
		var next time.Time
		if !disableCooling {
			if retryAfter != nil {
				next = now.Add(*retryAfter)
			} else {
				cooldown, nextLevel := nextQuotaCooldown(auth.Quota.BackoffLevel, disableCooling)
				if cooldown > 0 {
					next = now.Add(cooldown)
				}
				auth.Quota.BackoffLevel = nextLevel
			}
		}
		auth.Quota.NextRecoverAt = next
		auth.NextRetryAfter = next
	case 408, 500, 502, 503, 504:
		auth.StatusMessage = "transient upstream error"
		if disableCooling {
			auth.NextRetryAfter = time.Time{}
		} else {
			auth.NextRetryAfter = now.Add(1 * time.Minute)
		}
	default:
		if auth.StatusMessage == "" {
			auth.StatusMessage = "request failed"
		}
	}
}

// autoDisableReason 鐢ㄦ潵鍒ゆ柇杩欐澶辫触鏄惁搴旇瑙﹀彂鈥滆嚜鍔ㄥ仠鐢ㄢ€濄€?
// 褰撳墠瑙勫垯寰堢畝鍗曪細澶栧眰鐘舵€佺爜鏄?401锛屼笖閿欒鍐呭閲屼篃鑳借В鏋愬嚭 status=401锛屽氨璁や负搴旇鑷姩鍋滅敤銆?
func autoDisableReason(resultErr *Error) (string, bool) {
	// 鍏堟尅鎺夐潪 401 鍦烘櫙锛岄伩鍏嶆妸鍏朵粬閿欒璇垽鎴愰渶瑕佸仠鐢ㄣ€?
	if resultErr == nil {
		return "", false
	}

	// 鍘熷閿欒鍐呭鍚庨潰杩樿鐢ㄤ簬鐘舵€佽褰曞拰灞曠ず锛屾墍浠ヨ繖閲屽厛鍋氫竴娆″幓绌虹櫧澶勭悊銆?
	raw := strings.TrimSpace(resultErr.Message)
	if raw == "" {
		return "", false
	}

	// 杩欓噷鍙叧蹇冭繑鍥炰綋閲岀殑 status 瀛楁锛屼笉鍐嶇湅鍏朵粬閿欒鐮佹垨鏂囨銆?
	type providerErrorEnvelope struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}

	var parsed providerErrorEnvelope
	// 鍙湁褰撻敊璇唴瀹规槸鍚堟硶 JSON锛屽苟涓旈噷闈㈢殑 status 涔熸槸 401锛屾墠鐪熸瑙﹀彂鑷姩鍋滅敤銆?
	if !json.Valid([]byte(raw)) || json.Unmarshal([]byte(raw), &parsed) != nil {
		return "", false
	}
	if statusCodeFromResult(resultErr) == http.StatusUnauthorized && parsed.Status == http.StatusUnauthorized {
		return raw, true
	}
	// {"detail":"Unauthorized"}
	if strings.EqualFold(strings.TrimSpace(parsed.Detail), "Unauthorized") {
		return raw, true
	}
	return "", false
}

// disableAuthForPermanentFailure 璐熻矗鎶婁竴涓凡缁忕‘璁ゆ案涔呭け鏁堢殑 auth
// 鍒囨崲鎴愮鐢ㄧ姸鎬侊紝骞舵竻鎺夋墍鏈夆€滃畠杩樺彲浠ョ◢鍚庡啀璇曗€濈殑鐥曡抗銆?
func disableAuthForPermanentFailure(auth *Auth, result Result, reason string, now time.Time) {
	if auth == nil {
		return
	}
	statusMessage := FormatAutoDisabledStatusMessage(reason, now)
	// 鍏堝鐞?auth 绾у埆鐘舵€侊細
	// - Disabled=true 琛ㄧず杩欎釜 auth 宸叉槑纭笉鍙啀鐢?
	// - Unavailable=false 琛ㄧず瀹冧笉鏄€滄殏鏃朵笉鍙敤鈥濓紝鑰屾槸鈥滃凡缁忎笅绾库€?
	// - NextRetryAfter/Quota 娓呯┖锛岄伩鍏嶅畠缁х画璧伴噸璇曞拰闄愰鎭㈠閫昏緫
	auth.Disabled = true
	auth.Unavailable = false
	auth.Status = StatusDisabled
	auth.StatusMessage = statusMessage
	auth.UpdatedAt = now
	auth.NextRetryAfter = time.Time{}
	auth.Quota = QuotaState{}
	// LastError 缁х画淇濈暀鍘熷閿欒涓诧紝鍚庨潰鏁版嵁搴撲繚瀛樺拰鍓嶇灞曠ず閮借鐢ㄥ埌瀹冦€?
	auth.LastError = disabledResultError(result.Error, reason)

	if result.Model == "" {
		// 濡傛灉杩欐澶辫触涓嶆槸鏌愪釜鍏蜂綋妯″瀷瑙﹀彂鐨勶紝鍒拌繖閲屽氨澶熶簡銆?
		return
	}
	state := ensureModelState(auth, result.Model)
	// 濡傛灉杩欐澶辫触鏄煇涓叿浣撴ā鍨嬭Е鍙戠殑锛?
	// 杩欓噷鍐嶆妸妯″瀷绾х姸鎬佷篃鍚屾鏀规垚绂佺敤锛屼繚璇?auth 绾у拰妯″瀷绾ф樉绀轰竴鑷淬€?
	state.Status = StatusDisabled
	state.StatusMessage = statusMessage
	state.Unavailable = false
	state.NextRetryAfter = time.Time{}
	state.Quota = QuotaState{}
	state.UpdatedAt = now
	state.LastError = disabledResultError(result.Error, reason)
}

func disabledResultError(resultErr *Error, reason string) *Error {
	if resultErr == nil {
		// 鏋佺鎯呭喌涓嬪鏋滄嬁涓嶅埌涓婃父閿欒瀵硅薄锛?
		// 灏辨墜鍔ㄨˉ涓€涓厹搴曢敊璇紝閬垮厤鍚庣画钀藉簱鍜屽睍绀烘椂鎷夸笉鍒板師鍥犮€?
		return &Error{Code: "account_deactivated", Message: reason, HTTPStatus: http.StatusUnauthorized}
	}
	cloned := cloneError(resultErr)
	// 灏介噺琛ラ綈閿欒鐮佸拰鐘舵€佺爜锛屼繚璇佸悗缁姸鎬佸睍绀恒€佹暟鎹簱璁板綍鏇寸ǔ瀹氥€?
	if strings.TrimSpace(cloned.Code) == "" {
		cloned.Code = "account_deactivated"
	}
	if cloned.HTTPStatus == 0 {
		cloned.HTTPStatus = http.StatusUnauthorized
	}
	return cloned
}

// nextQuotaCooldown returns the next cooldown duration and updated backoff level for repeated quota errors.
func nextQuotaCooldown(prevLevel int, disableCooling bool) (time.Duration, int) {
	if prevLevel < 0 {
		prevLevel = 0
	}
	if disableCooling {
		return 0, prevLevel
	}
	cooldown := quotaBackoffBase * time.Duration(1<<prevLevel)
	if cooldown < quotaBackoffBase {
		cooldown = quotaBackoffBase
	}
	if cooldown >= quotaBackoffMax {
		return quotaBackoffMax, prevLevel
	}
	return cooldown, prevLevel + 1
}

// List returns all auth entries currently known by the manager.
func (m *Manager) List() []*Auth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*Auth, 0, len(m.auths))
	for _, auth := range m.auths {
		list = append(list, auth.Clone())
	}
	return list
}

// GetByID retrieves an auth entry by its ID.

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

// CloseExecutionSession asks all registered executors to release the supplied execution session.
func (m *Manager) CloseExecutionSession(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if m == nil || sessionID == "" {
		return
	}

	m.mu.RLock()
	executors := make([]ProviderExecutor, 0, len(m.executors))
	for _, exec := range m.executors {
		executors = append(executors, exec)
	}
	m.mu.RUnlock()

	for i := range executors {
		if closer, ok := executors[i].(ExecutionSessionCloser); ok && closer != nil {
			closer.CloseExecutionSession(sessionID)
		}
	}
}

func (m *Manager) useSchedulerFastPath() bool {
	if m == nil || m.scheduler == nil {
		return false
	}
	return isBuiltInSelector(m.selector)
}

func shouldRetrySchedulerPick(err error) bool {
	if err == nil {
		return false
	}
	var cooldownErr *modelCooldownError
	if errors.As(err, &cooldownErr) {
		return true
	}
	var authErr *Error
	if !errors.As(err, &authErr) || authErr == nil {
		return false
	}
	return authErr.Code == "auth_not_found" || authErr.Code == "auth_unavailable"
}

func (m *Manager) routeAwareSelectionRequired(auth *Auth, routeModel string) bool {
	if auth == nil || strings.TrimSpace(routeModel) == "" {
		return false
	}
	return m.selectionModelKeyForAuth(auth, routeModel) != canonicalModelKey(routeModel)
}

func (m *Manager) pickNextLegacy(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, ProviderExecutor, error) {
	pinnedAuthID := pinnedAuthIDFromMetadata(opts.Metadata)

	m.mu.RLock()
	executor, okExecutor := m.executors[provider]
	if !okExecutor {
		m.mu.RUnlock()
		return nil, nil, &Error{Code: "executor_not_found", Message: "executor not registered"}
	}
	candidates := make([]*Auth, 0, len(m.auths))
	modelKey := strings.TrimSpace(model)
	// Always use base model name (without thinking suffix) for auth matching.
	if modelKey != "" {
		parsed := thinking.ParseSuffix(modelKey)
		if parsed.ModelName != "" {
			modelKey = strings.TrimSpace(parsed.ModelName)
		}
	}
	registryRef := registry.GetGlobalRegistry()
	for _, candidate := range m.auths {
		if candidate.Provider != provider || candidate.Disabled {
			continue
		}
		if pinnedAuthID != "" && candidate.ID != pinnedAuthID {
			continue
		}
		if _, used := tried[candidate.ID]; used {
			continue
		}
		if modelKey != "" && !m.authSupportsRouteModel(registryRef, candidate, model) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		m.mu.RUnlock()
		return nil, nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	available, errAvailable := m.availableAuthsForRouteModel(candidates, provider, model, time.Now())
	if errAvailable != nil {
		m.mu.RUnlock()
		return nil, nil, errAvailable
	}
	selected, errPick := m.selector.Pick(ctx, provider, selectionArgForSelector(m.selector, model), opts, available)
	if errPick != nil {
		m.mu.RUnlock()
		return nil, nil, errPick
	}
	if selected == nil {
		m.mu.RUnlock()
		return nil, nil, &Error{Code: "auth_not_found", Message: "selector returned no auth"}
	}
	authCopy := selected.Clone()
	m.mu.RUnlock()
	if !selected.indexAssigned {
		m.mu.Lock()
		if current := m.auths[authCopy.ID]; current != nil && !current.indexAssigned {
			current.EnsureIndex()
			authCopy = current.Clone()
		}
		m.mu.Unlock()
	}
	return authCopy, executor, nil
}

func (m *Manager) pickNext(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, ProviderExecutor, error) {
	if !m.useSchedulerFastPath() {
		return m.pickNextLegacy(ctx, provider, model, opts, tried)
	}
	if strings.TrimSpace(model) != "" {
		m.mu.RLock()
		for _, candidate := range m.auths {
			if candidate == nil || candidate.Provider != provider || candidate.Disabled {
				continue
			}
			if _, used := tried[candidate.ID]; used {
				continue
			}
			if m.routeAwareSelectionRequired(candidate, model) {
				m.mu.RUnlock()
				return m.pickNextLegacy(ctx, provider, model, opts, tried)
			}
		}
		m.mu.RUnlock()
	}
	executor, okExecutor := m.Executor(provider)
	if !okExecutor {
		return nil, nil, &Error{Code: "executor_not_found", Message: "executor not registered"}
	}
	selected, errPick := m.scheduler.pickSingle(ctx, provider, model, opts, tried)
	if errPick != nil && model != "" && shouldRetrySchedulerPick(errPick) {
		m.syncScheduler()
		selected, errPick = m.scheduler.pickSingle(ctx, provider, model, opts, tried)
	}
	if errPick != nil {
		return nil, nil, errPick
	}
	if selected == nil {
		return nil, nil, &Error{Code: "auth_not_found", Message: "selector returned no auth"}
	}
	authCopy := selected.Clone()
	if !selected.indexAssigned {
		m.mu.Lock()
		if current := m.auths[authCopy.ID]; current != nil && !current.indexAssigned {
			current.EnsureIndex()
			authCopy = current.Clone()
		}
		m.mu.Unlock()
	}
	return authCopy, executor, nil
}

func (m *Manager) pickNextMixedLegacy(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, ProviderExecutor, string, error) {
	pinnedAuthID := pinnedAuthIDFromMetadata(opts.Metadata)

	providerSet := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		p := strings.TrimSpace(strings.ToLower(provider))
		if p == "" {
			continue
		}
		providerSet[p] = struct{}{}
	}
	if len(providerSet) == 0 {
		return nil, nil, "", &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}

	m.mu.RLock()
	candidates := make([]*Auth, 0, len(m.auths))
	modelKey := strings.TrimSpace(model)
	// Always use base model name (without thinking suffix) for auth matching.
	if modelKey != "" {
		parsed := thinking.ParseSuffix(modelKey)
		if parsed.ModelName != "" {
			modelKey = strings.TrimSpace(parsed.ModelName)
		}
	}
	registryRef := registry.GetGlobalRegistry()
	for _, candidate := range m.auths {
		if candidate == nil || candidate.Disabled {
			continue
		}
		if pinnedAuthID != "" && candidate.ID != pinnedAuthID {
			continue
		}
		providerKey := strings.TrimSpace(strings.ToLower(candidate.Provider))
		if providerKey == "" {
			continue
		}
		if _, ok := providerSet[providerKey]; !ok {
			continue
		}
		if _, used := tried[candidate.ID]; used {
			continue
		}
		if _, ok := m.executors[providerKey]; !ok {
			continue
		}
		if modelKey != "" && !m.authSupportsRouteModel(registryRef, candidate, model) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		m.mu.RUnlock()
		return nil, nil, "", &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	available, errAvailable := m.availableAuthsForRouteModel(candidates, "mixed", model, time.Now())
	if errAvailable != nil {
		m.mu.RUnlock()
		return nil, nil, "", errAvailable
	}
	selected, errPick := m.selector.Pick(ctx, "mixed", selectionArgForSelector(m.selector, model), opts, available)
	if errPick != nil {
		m.mu.RUnlock()
		return nil, nil, "", errPick
	}
	if selected == nil {
		m.mu.RUnlock()
		return nil, nil, "", &Error{Code: "auth_not_found", Message: "selector returned no auth"}
	}
	providerKey := strings.TrimSpace(strings.ToLower(selected.Provider))
	executor, okExecutor := m.executors[providerKey]
	if !okExecutor {
		m.mu.RUnlock()
		return nil, nil, "", &Error{Code: "executor_not_found", Message: "executor not registered"}
	}
	authCopy := selected.Clone()
	m.mu.RUnlock()
	if !selected.indexAssigned {
		m.mu.Lock()
		if current := m.auths[authCopy.ID]; current != nil && !current.indexAssigned {
			current.EnsureIndex()
			authCopy = current.Clone()
		}
		m.mu.Unlock()
	}
	return authCopy, executor, providerKey, nil
}

func (m *Manager) pickNextMixed(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, ProviderExecutor, string, error) {
	if !m.useSchedulerFastPath() {
		return m.pickNextMixedLegacy(ctx, providers, model, opts, tried)
	}

	eligibleProviders := make([]string, 0, len(providers))
	seenProviders := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		providerKey := strings.TrimSpace(strings.ToLower(provider))
		if providerKey == "" {
			continue
		}
		if _, seen := seenProviders[providerKey]; seen {
			continue
		}
		if _, okExecutor := m.Executor(providerKey); !okExecutor {
			continue
		}
		seenProviders[providerKey] = struct{}{}
		eligibleProviders = append(eligibleProviders, providerKey)
	}
	if len(eligibleProviders) == 0 {
		return nil, nil, "", &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	if strings.TrimSpace(model) != "" {
		providerSet := make(map[string]struct{}, len(eligibleProviders))
		for _, providerKey := range eligibleProviders {
			providerSet[providerKey] = struct{}{}
		}
		m.mu.RLock()
		for _, candidate := range m.auths {
			if candidate == nil || candidate.Disabled {
				continue
			}
			if _, ok := providerSet[strings.TrimSpace(strings.ToLower(candidate.Provider))]; !ok {
				continue
			}
			if _, used := tried[candidate.ID]; used {
				continue
			}
			if m.routeAwareSelectionRequired(candidate, model) {
				m.mu.RUnlock()
				return m.pickNextMixedLegacy(ctx, providers, model, opts, tried)
			}
		}
		m.mu.RUnlock()
	}

	selected, providerKey, errPick := m.scheduler.pickMixed(ctx, eligibleProviders, model, opts, tried)
	if errPick != nil && model != "" && shouldRetrySchedulerPick(errPick) {
		m.syncScheduler()
		selected, providerKey, errPick = m.scheduler.pickMixed(ctx, eligibleProviders, model, opts, tried)
	}
	if errPick != nil {
		if log.IsLevelEnabled(log.DebugLevel) {
			entry := logEntryWithRequestID(ctx)
			pinned := pinnedAuthIDFromMetadata(opts.Metadata)
			entry.Debugf("scheduler pick failed (providers=%v model=%s pinned_auth_id=%s tried=%d): %v", eligibleProviders, model, pinned, len(tried), errPick)
		}
		return nil, nil, "", errPick
	}
	if selected == nil {
		return nil, nil, "", &Error{Code: "auth_not_found", Message: "selector returned no auth"}
	}
	executor, okExecutor := m.Executor(providerKey)
	if !okExecutor {
		return nil, nil, "", &Error{Code: "executor_not_found", Message: "executor not registered"}
	}
	authCopy := selected.Clone()
	if !selected.indexAssigned {
		m.mu.Lock()
		if current := m.auths[authCopy.ID]; current != nil && !current.indexAssigned {
			current.EnsureIndex()
			authCopy = current.Clone()
		}
		m.mu.Unlock()
	}
	return authCopy, executor, providerKey, nil
}

func (m *Manager) persist(ctx context.Context, auth *Auth) error {
	if m.store == nil || auth == nil {
		return nil
	}
	if shouldSkipPersist(ctx) {
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

// StartAutoRefresh launches a background loop that evaluates auth freshness
// every few seconds and triggers refresh operations when required.
// Only one loop is kept alive; starting a new one cancels the previous run.
func (m *Manager) StartAutoRefresh(parent context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = refreshCheckInterval
	}

	m.mu.Lock()
	cancelPrev := m.refreshCancel
	m.refreshCancel = nil
	m.refreshLoop = nil
	m.mu.Unlock()
	if cancelPrev != nil {
		cancelPrev()
	}

	ctx, cancelCtx := context.WithCancel(parent)
	workers := refreshMaxConcurrency
	if cfg, ok := m.runtimeConfig.Load().(*internalconfig.Config); ok && cfg != nil && cfg.AuthAutoRefreshWorkers > 0 {
		workers = cfg.AuthAutoRefreshWorkers
	}
	loop := newAuthAutoRefreshLoop(m, interval, workers)

	m.mu.Lock()
	m.refreshCancel = cancelCtx
	m.refreshLoop = loop
	m.mu.Unlock()

	loop.rebuild(time.Now())
	go loop.run(ctx)
}

// StartAutoRefreshLocal keeps the standard refresh loop and adds periodic
// OAuth health probes used by local deployments.
func (m *Manager) StartAutoRefreshLocal(parent context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = refreshCheckInterval
	}

	m.mu.Lock()
	cancelPrev := m.refreshCancel
	m.refreshCancel = nil
	m.refreshLoop = nil
	m.mu.Unlock()
	if cancelPrev != nil {
		cancelPrev()
	}

	ctx, cancelCtx := context.WithCancel(parent)
	workers := refreshMaxConcurrency
	if cfg, ok := m.runtimeConfig.Load().(*internalconfig.Config); ok && cfg != nil && cfg.AuthAutoRefreshWorkers > 0 {
		workers = cfg.AuthAutoRefreshWorkers
	}
	loop := newAuthAutoRefreshLoop(m, interval, workers)

	m.mu.Lock()
	m.refreshCancel = cancelCtx
	m.refreshLoop = loop
	m.mu.Unlock()

	loop.rebuild(time.Now())
	go loop.run(ctx)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		m.checkAuthHealthProbesLocal(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.checkAuthHealthProbesLocal(ctx)
			}
		}
	}()
}

// StopAutoRefresh cancels the background refresh loop, if running.
func (m *Manager) StopAutoRefresh() {
	m.mu.Lock()
	cancel := m.refreshCancel
	m.refreshCancel = nil
	m.refreshLoop = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (m *Manager) queueRefreshReschedule(authID string) {
	if m == nil || authID == "" {
		return
	}
	m.mu.RLock()
	loop := m.refreshLoop
	m.mu.RUnlock()
	if loop == nil {
		return
	}
	loop.queueReschedule(authID)
}

func (m *Manager) snapshotKnownAuths() []*Auth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Auth, 0, len(m.auths)+len(m.inactiveAuths))
	for _, a := range m.auths {
		out = append(out, a.Clone())
	}
	for _, a := range m.inactiveAuths {
		out = append(out, a.Clone())
	}
	return out
}

func (m *Manager) shouldRefresh(a *Auth, now time.Time) bool {
	if a == nil || a.Disabled {
		return false
	}
	if !a.NextRefreshAfter.IsZero() && now.Before(a.NextRefreshAfter) {
		return false
	}
	if evaluator, ok := a.Runtime.(RefreshEvaluator); ok && evaluator != nil {
		return evaluator.ShouldRefresh(now, a)
	}

	lastRefresh := a.LastRefreshedAt
	if lastRefresh.IsZero() {
		if ts, ok := authLastRefreshTimestamp(a); ok {
			lastRefresh = ts
		}
	}

	expiry, hasExpiry := a.ExpirationTime()

	if interval := authPreferredInterval(a); interval > 0 {
		if hasExpiry && !expiry.IsZero() {
			if !expiry.After(now) {
				return true
			}
			if expiry.Sub(now) <= interval {
				return true
			}
		}
		if lastRefresh.IsZero() {
			return true
		}
		return now.Sub(lastRefresh) >= interval
	}

	provider := strings.ToLower(a.Provider)
	lead := ProviderRefreshLead(provider, a.Runtime)
	if lead == nil {
		return false
	}
	if *lead <= 0 {
		if hasExpiry && !expiry.IsZero() {
			return now.After(expiry)
		}
		return false
	}
	if hasExpiry && !expiry.IsZero() {
		return time.Until(expiry) <= *lead
	}
	if !lastRefresh.IsZero() {
		return now.Sub(lastRefresh) >= *lead
	}
	return true
}

func authPreferredInterval(a *Auth) time.Duration {
	if a == nil {
		return 0
	}
	if d := durationFromMetadata(a.Metadata, "refresh_interval_seconds", "refreshIntervalSeconds", "refresh_interval", "refreshInterval"); d > 0 {
		return d
	}
	if d := durationFromAttributes(a.Attributes, "refresh_interval_seconds", "refreshIntervalSeconds", "refresh_interval", "refreshInterval"); d > 0 {
		return d
	}
	return 0
}

func durationFromMetadata(meta map[string]any, keys ...string) time.Duration {
	if len(meta) == 0 {
		return 0
	}
	for _, key := range keys {
		if val, ok := meta[key]; ok {
			if dur := parseDurationValue(val); dur > 0 {
				return dur
			}
		}
	}
	return 0
}

func durationFromAttributes(attrs map[string]string, keys ...string) time.Duration {
	if len(attrs) == 0 {
		return 0
	}
	for _, key := range keys {
		if val, ok := attrs[key]; ok {
			if dur := parseDurationString(val); dur > 0 {
				return dur
			}
		}
	}
	return 0
}

func parseDurationValue(val any) time.Duration {
	switch v := val.(type) {
	case time.Duration:
		if v <= 0 {
			return 0
		}
		return v
	case int:
		if v <= 0 {
			return 0
		}
		return time.Duration(v) * time.Second
	case int32:
		if v <= 0 {
			return 0
		}
		return time.Duration(v) * time.Second
	case int64:
		if v <= 0 {
			return 0
		}
		return time.Duration(v) * time.Second
	case uint:
		if v == 0 {
			return 0
		}
		return time.Duration(v) * time.Second
	case uint32:
		if v == 0 {
			return 0
		}
		return time.Duration(v) * time.Second
	case uint64:
		if v == 0 {
			return 0
		}
		return time.Duration(v) * time.Second
	case float32:
		if v <= 0 {
			return 0
		}
		return time.Duration(float64(v) * float64(time.Second))
	case float64:
		if v <= 0 {
			return 0
		}
		return time.Duration(v * float64(time.Second))
	case json.Number:
		if i, err := v.Int64(); err == nil {
			if i <= 0 {
				return 0
			}
			return time.Duration(i) * time.Second
		}
		if f, err := v.Float64(); err == nil && f > 0 {
			return time.Duration(f * float64(time.Second))
		}
	case string:
		return parseDurationString(v)
	}
	return 0
}

func parseDurationString(raw string) time.Duration {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0
	}
	if dur, err := time.ParseDuration(s); err == nil && dur > 0 {
		return dur
	}
	if secs, err := strconv.ParseFloat(s, 64); err == nil && secs > 0 {
		return time.Duration(secs * float64(time.Second))
	}
	return 0
}

func authLastRefreshTimestamp(a *Auth) (time.Time, bool) {
	if a == nil {
		return time.Time{}, false
	}
	if a.Metadata != nil {
		if ts, ok := lookupMetadataTime(a.Metadata, "last_refresh", "lastRefresh", "last_refreshed_at", "lastRefreshedAt"); ok {
			return ts, true
		}
	}
	if a.Attributes != nil {
		for _, key := range []string{"last_refresh", "lastRefresh", "last_refreshed_at", "lastRefreshedAt"} {
			if val := strings.TrimSpace(a.Attributes[key]); val != "" {
				if ts, ok := parseTimeValue(val); ok {
					return ts, true
				}
			}
		}
	}
	return time.Time{}, false
}

func lookupMetadataTime(meta map[string]any, keys ...string) (time.Time, bool) {
	for _, key := range keys {
		if val, ok := meta[key]; ok {
			if ts, ok1 := parseTimeValue(val); ok1 {
				return ts, true
			}
		}
	}
	return time.Time{}, false
}

func (m *Manager) markRefreshPending(id string, now time.Time) bool {
	m.mu.Lock()
	auth, ok := m.auths[id]
	if !ok || auth == nil || auth.Disabled {
		m.mu.Unlock()
		return false
	}
	if !auth.NextRefreshAfter.IsZero() && now.Before(auth.NextRefreshAfter) {
		m.mu.Unlock()
		return false
	}
	auth.NextRefreshAfter = now.Add(refreshPendingBackoff)
	m.auths[id] = auth
	m.mu.Unlock()

	m.queueRefreshReschedule(id)
	return true
}

func (m *Manager) refreshAuth(ctx context.Context, id string) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.RLock()
	auth := m.auths[id]
	var exec ProviderExecutor
	if auth != nil {
		exec = m.executors[auth.Provider]
	}
	m.mu.RUnlock()
	if auth == nil || exec == nil {
		return
	}
	cloned := auth.Clone()
	updated, err := exec.Refresh(ctx, cloned)
	if err != nil && errors.Is(err, context.Canceled) {
		log.Debugf("refresh canceled for %s, %s", auth.Provider, auth.ID)
		return
	}
	log.Debugf("refreshed %s, %s, %v", auth.Provider, auth.ID, err)
	now := time.Now()
	if err != nil {
		shouldReschedule := false
		m.mu.Lock()
		if current := m.auths[id]; current != nil {
			current.NextRefreshAfter = now.Add(refreshFailureBackoff)
			current.LastError = &Error{Message: err.Error()}
			m.auths[id] = current
			shouldReschedule = true
			if m.scheduler != nil {
				m.scheduler.upsertAuth(current.Clone())
			}
		}
		m.mu.Unlock()
		if shouldReschedule {
			m.queueRefreshReschedule(id)
		}
		return
	}
	if updated == nil {
		updated = cloned
	}
	// Preserve runtime created by the executor during Refresh.
	// If executor didn't set one, fall back to the previous runtime.
	if updated.Runtime == nil {
		updated.Runtime = auth.Runtime
	}
	updated.LastRefreshedAt = now
	updated.NextRefreshAfter = time.Time{}
	updated.LastError = nil
	updated.UpdatedAt = now
	_, _ = m.Update(ctx, updated)
}

func (m *Manager) executorFor(provider string) ProviderExecutor {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.executors[provider]
}

// roundTripperContextKey is an unexported context key type to avoid collisions.
type roundTripperContextKey struct{}

// roundTripperFor retrieves an HTTP RoundTripper for the given auth if a provider is registered.
func (m *Manager) roundTripperFor(auth *Auth) http.RoundTripper {
	m.mu.RLock()
	p := m.rtProvider
	m.mu.RUnlock()
	if p == nil || auth == nil {
		return nil
	}
	return p.RoundTripperFor(auth)
}

// RoundTripperProvider defines a minimal provider of per-auth HTTP transports.
type RoundTripperProvider interface {
	RoundTripperFor(auth *Auth) http.RoundTripper
}

// RequestPreparer is an optional interface that provider executors can implement
// to mutate outbound HTTP requests with provider credentials.
type RequestPreparer interface {
	PrepareRequest(req *http.Request, auth *Auth) error
}

func executorKeyFromAuth(auth *Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		providerKey := strings.TrimSpace(auth.Attributes["provider_key"])
		compatName := strings.TrimSpace(auth.Attributes["compat_name"])
		if compatName != "" {
			if providerKey == "" {
				providerKey = compatName
			}
			return strings.ToLower(providerKey)
		}
	}
	return strings.ToLower(strings.TrimSpace(auth.Provider))
}

// logEntryWithRequestID returns a logrus entry with request_id field if available in context.
func logEntryWithRequestID(ctx context.Context) *log.Entry {
	if ctx == nil {
		return log.NewEntry(log.StandardLogger())
	}
	if reqID := logging.GetRequestID(ctx); reqID != "" {
		return log.WithField("request_id", reqID)
	}
	return log.NewEntry(log.StandardLogger())
}

func debugLogAuthSelection(entry *log.Entry, auth *Auth, provider string, model string) {
	if !log.IsLevelEnabled(log.DebugLevel) {
		return
	}
	if entry == nil || auth == nil {
		return
	}
	accountType, accountInfo := auth.AccountInfo()
	proxyInfo := auth.ProxyInfo()
	suffix := ""
	if proxyInfo != "" {
		suffix = " " + proxyInfo
	}
	switch accountType {
	case "api_key":
		entry.Debugf("Use API key %s for model %s%s", util.HideAPIKey(accountInfo), model, suffix)
	case "oauth":
		ident := formatOauthIdentity(auth, provider, accountInfo)
		entry.Debugf("Use OAuth %s for model %s%s", ident, model, suffix)
	}
}

func formatOauthIdentity(auth *Auth, provider string, accountInfo string) string {
	if auth == nil {
		return ""
	}
	// Prefer the auth's provider when available.
	providerName := strings.TrimSpace(auth.Provider)
	if providerName == "" {
		providerName = strings.TrimSpace(provider)
	}
	// Only log the basename to avoid leaking host paths.
	// FileName may be unset for some auth backends; fall back to ID.
	authFile := strings.TrimSpace(auth.FileName)
	if authFile == "" {
		authFile = strings.TrimSpace(auth.ID)
	}
	if authFile != "" {
		authFile = filepath.Base(authFile)
	}
	parts := make([]string, 0, 3)
	if providerName != "" {
		parts = append(parts, "provider="+providerName)
	}
	if authFile != "" {
		parts = append(parts, "auth_file="+authFile)
	}
	if len(parts) == 0 {
		return accountInfo
	}
	return strings.Join(parts, " ")
}

// InjectCredentials delegates per-provider HTTP request preparation when supported.
// If the registered executor for the auth provider implements RequestPreparer,
// it will be invoked to modify the request (e.g., add headers).
func (m *Manager) InjectCredentials(req *http.Request, authID string) error {
	if req == nil || authID == "" {
		return nil
	}
	m.mu.RLock()
	a := m.auths[authID]
	var exec ProviderExecutor
	if a != nil {
		exec = m.executors[executorKeyFromAuth(a)]
	}
	m.mu.RUnlock()
	if a == nil || exec == nil {
		return nil
	}
	if p, ok := exec.(RequestPreparer); ok && p != nil {
		return p.PrepareRequest(req, a)
	}
	return nil
}

// PrepareHttpRequest injects provider credentials into the supplied HTTP request.
func (m *Manager) PrepareHttpRequest(ctx context.Context, auth *Auth, req *http.Request) error {
	if m == nil {
		return &Error{Code: "provider_not_found", Message: "manager is nil"}
	}
	if auth == nil {
		return &Error{Code: "auth_not_found", Message: "auth is nil"}
	}
	if req == nil {
		return &Error{Code: "invalid_request", Message: "http request is nil"}
	}
	if ctx != nil {
		*req = *req.WithContext(ctx)
	}
	providerKey := executorKeyFromAuth(auth)
	if providerKey == "" {
		return &Error{Code: "provider_not_found", Message: "auth provider is empty"}
	}
	exec := m.executorFor(providerKey)
	if exec == nil {
		return &Error{Code: "provider_not_found", Message: "executor not registered for provider: " + providerKey}
	}
	preparer, ok := exec.(RequestPreparer)
	if !ok || preparer == nil {
		return &Error{Code: "not_supported", Message: "executor does not support http request preparation"}
	}
	return preparer.PrepareRequest(req, auth)
}

// NewHttpRequest constructs a new HTTP request and injects provider credentials into it.
func (m *Manager) NewHttpRequest(ctx context.Context, auth *Auth, method, targetURL string, body []byte, headers http.Header) (*http.Request, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	method = strings.TrimSpace(method)
	if method == "" {
		method = http.MethodGet
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, targetURL, reader)
	if err != nil {
		return nil, err
	}
	if headers != nil {
		httpReq.Header = headers.Clone()
	}
	if errPrepare := m.PrepareHttpRequest(ctx, auth, httpReq); errPrepare != nil {
		return nil, errPrepare
	}
	return httpReq, nil
}

// HttpRequest injects provider credentials into the supplied HTTP request and executes it.
func (m *Manager) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	if m == nil {
		return nil, &Error{Code: "provider_not_found", Message: "manager is nil"}
	}
	if auth == nil {
		return nil, &Error{Code: "auth_not_found", Message: "auth is nil"}
	}
	if req == nil {
		return nil, &Error{Code: "invalid_request", Message: "http request is nil"}
	}
	providerKey := executorKeyFromAuth(auth)
	if providerKey == "" {
		return nil, &Error{Code: "provider_not_found", Message: "auth provider is empty"}
	}
	exec := m.executorFor(providerKey)
	if exec == nil {
		return nil, &Error{Code: "provider_not_found", Message: "executor not registered for provider: " + providerKey}
	}
	return exec.HttpRequest(ctx, auth, req)
}
