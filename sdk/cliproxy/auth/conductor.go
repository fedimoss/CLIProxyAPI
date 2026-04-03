package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
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
	healthProbeMaxWorkers = 8
	quotaBackoffBase      = time.Second
	quotaBackoffMax       = 30 * time.Minute

	// 周额度剩余比例低于这个阈值时，测活会把账号标记为额度不足。
	healthProbeMinimumRemainingWeeklyPercent = 90
	// 本地健康复检沿用 codex CLI 的 User-Agent，尽量贴近真实请求环境。
	codexHealthProbeUserAgent = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
	// 健康复检改写账号状态后，单独给落库预留一个较短超时，避免被探测请求的超时连带取消。
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
	refreshCancel    context.CancelFunc
	refreshSemaphore chan struct{}
	// 本地健康复检状态
	healthSemaphore chan struct{} // 限制本地健康复检的全局并发数（最多 healthProbeMaxWorkers 个同时进行）
	healthProbeAt   sync.Map      // 记录每个 auth 上一次复检时间，用于最小间隔控制（key: authID, value: time.Time）
	healthProbeBusy sync.Map      // 标记正在被复检的 auth，防止同一个 auth 同时跑多个探测（key: authID, value: struct{}）
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
		refreshSemaphore: make(chan struct{}, refreshMaxConcurrency),
		healthSemaphore:  make(chan struct{}, healthProbeMaxWorkers),
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
	m.rebuildAPIKeyModelAliasFromRuntimeConfig()
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

func filterExecutionModels(auth *Auth, routeModel string, candidates []string, pooled bool) []string {
	if len(candidates) == 0 {
		return nil
	}
	now := time.Now()
	out := make([]string, 0, len(candidates))
	for _, upstreamModel := range candidates {
		stateModel := executionResultModel(routeModel, upstreamModel, pooled)
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
	return filterExecutionModels(auth, routeModel, candidates, pooled), pooled
}

func (m *Manager) prepareExecutionModels(auth *Auth, routeModel string) []string {
	models, _ := m.preparedExecutionModels(auth, routeModel)
	return models
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
		resultModel := executionResultModel(routeModel, execModel, pooled)
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
			resultModel := executionResultModel(routeModel, upstreamModel, pooled)
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
			resultModel := executionResultModel(routeModel, upstreamModel, pooled)
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
		blocked, reason, next := isAuthBlockedForModel(auth, model, now)
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

func (m *Manager) shouldRetryAfterError(err error, attempt int, providers []string, model string, maxWait time.Duration) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}
	if maxWait <= 0 {
		return 0, false
	}
	if status := statusCodeFromError(err); status == http.StatusOK {
		return 0, false
	}
	if isRequestInvalidError(err) {
		return 0, false
	}
	wait, found := m.closestCooldownWait(providers, model, attempt)
	if !found || wait > maxWait {
		return 0, false
	}
	return wait, true
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
			// 请求失败后，先尝试判断这次失败是否属于“这个 OAuth 已经永久失效”的情况。
			// 如果命中这种情况，就不要再把它当作临时失败处理，而是直接走自动停用流程。
			if reason, okDisable := autoDisableReason(result.Error); okDisable {
				// 与 Python 测活脚本保持一致：区分“额度不足”和“账号失活”。
				// 先用 extractCliproxyFailureReasonLocal 检查错误内容里是否包含额度不足信号
				// (rate_limit、usage_limit_reached、remaining_percent 低于阈值等)。
				// 如果命中额度问题 → DBStatus=3 (可复检恢复)，否则 → DBStatus=2 (永久停用)。
				failure := extractCliproxyFailureReasonLocal(result.Error.Message, m.oauthHealthProbeMinRemainingWeeklyPercent())
				if failure != nil && failure.QuotaLimited {
					// ── 额度不足：账号还活着，只是暂时不能用 ──
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
					// ── 账号失活：永久停用 ──
					auth.DBStatus = DBStatusDisabled
					disableAuthForPermanentFailure(auth, result, reason, now)
				}
				// 立刻写回数据库，保证服务重启后仍然保持对应状态。
				_ = m.persist(ctx, auth)
				// 准备一份最新快照，后面交给调度器和管理页同步显示。
				authSnapshot = auth.Clone()
				// 标记稍后撤掉这个 auth 对应的模型注册。
				// 这样后续请求路由时，就不会再选到它。
				shouldUnregisterClient = true
			} else if result.Model != "" {
				if !isRequestScopedNotFoundResultError(result.Error) {
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
							next := now.Add(30 * time.Minute)
							state.NextRetryAfter = next
							suspendReason = "unauthorized"
							shouldSuspendModel = true
						case 402, 403:
							next := now.Add(30 * time.Minute)
							state.NextRetryAfter = next
							suspendReason = "payment_required"
							shouldSuspendModel = true
						case 404:
							next := now.Add(12 * time.Hour)
							state.NextRetryAfter = next
							suspendReason = "not_found"
							shouldSuspendModel = true
						case 429:
							var next time.Time
							backoffLevel := state.Quota.BackoffLevel
							if result.RetryAfter != nil {
								next = now.Add(*result.RetryAfter)
							} else {
								cooldown, nextLevel := nextQuotaCooldown(backoffLevel, quotaCooldownDisabledForAuth(auth))
								if cooldown > 0 {
									next = now.Add(cooldown)
								}
								backoffLevel = nextLevel
							}
							state.NextRetryAfter = next
							state.Quota = QuotaState{
								Exceeded:      true,
								Reason:        "quota",
								NextRecoverAt: next,
								BackoffLevel:  backoffLevel,
							}
							suspendReason = "quota"
							shouldSuspendModel = true
							setModelQuota = true
						case 408, 500, 502, 503, 504:
							if quotaCooldownDisabledForAuth(auth) {
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
		// 这里才真正把这个 auth 对应的模型从注册表里移除。
		// 即使它还保留在内存 auth 列表中，也不会再参与后续请求路由。
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

// MarkResultLocal 复用原有结果处理逻辑，并在本地版流程中为成功的 OAuth
// 请求补上一条后台健康复检链路。
func (m *Manager) MarkResultLocal(ctx context.Context, result Result) {
	m.MarkResult(ctx, result)
	if m == nil || !result.Success {
		return
	}
	// 只有主请求已经成功时，才在后台补做一次“额度/健康”复检。
	// 这样不会拖慢当前响应，但能尽快把已经失效的 OAuth 清出可用池。
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

// authHealthProbeDecisionLocal 表示一次测活后的最终落库结果。
// DBStatus 会直接影响账号是否继续轮询、是否继续参与后续定时复检。
type authHealthProbeDecisionLocal struct {
	DBStatus   int
	HTTPStatus int
	Reason     string
}

// scheduleAuthHealthProbeLocal 异步触发单个 auth 的本地健康复检。
// 这里故意不阻塞当前请求，让复检结果只影响后续请求。
func (m *Manager) scheduleAuthHealthProbeLocal(authID string) {
	authID = strings.TrimSpace(authID)
	if m == nil || authID == "" {
		return
	}
	go m.runAuthHealthProbeWithLimitLocal(context.Background(), authID)
}

// checkAuthHealthProbesLocal 用于定时巡检仍可被复检的 OAuth 账号（DBStatus 为 1 或 3）。
// 它和”成功后异步复检”共用同一套底层探测逻辑，只是触发时机不同。
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
		log.Infof("复检开始了")
	}
	for _, auth := range pending {
		go m.runAuthHealthProbeWithLimitLocal(ctx, auth.ID)
	}
}

// runAuthHealthProbeWithLimitLocal 负责给本地健康复检加两层保护：
// 1. 同一个 auth 同一时间只允许跑一个复检；
// 2. 全局并发数受限，避免一次性打太多探测请求。
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

	if m.healthSemaphore == nil {
		m.runAuthHealthProbeLocal(ctx, auth)
		return
	}
	select {
	case m.healthSemaphore <- struct{}{}:
		defer func() { <-m.healthSemaphore }()
	case <-ctx.Done():
		return
	}
	m.runAuthHealthProbeLocal(ctx, auth)
}

// beginAuthHealthProbeLocal 判断这次复检是否允许开始。
// 这里会做最小间隔控制，避免同一个 auth 在短时间内被反复探测。
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

// endAuthHealthProbeLocal 在复检结束后释放“正在复检”的占位标记。
func (m *Manager) endAuthHealthProbeLocal(authID string) {
	if m == nil {
		return
	}
	m.healthProbeBusy.Delete(strings.TrimSpace(authID))
}

// runAuthHealthProbeLocal 真正执行一次健康复检。
// 探测结果通过 classifyAuthHealthProbeLocal 分类为三态：
// 正常（DBStatus=1）、额度不足（DBStatus=3）、账号失活（DBStatus=2），
// 再通过 applyAuthHealthProbeDecisionLocal 写回 auth 并落库。
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
			// 这类 "Get \"https://chatgpt.com/backend-api/wham/usage\": context deadline exceeded"
			// 更像一次临时探测失败，不像账号已经彻底失活。
			// 这里改落到状态 3，等待下一次定时复检重新判断，而不是直接打成状态 2。
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

// classifyAuthHealthProbeLocal 根据测活响应的 HTTP 状态码和内容，分类为三种落库结果：
// 正常（DBStatus=1）、额度不足（DBStatus=3）、账号失活（DBStatus=2）。
func (m *Manager) classifyAuthHealthProbeLocal(httpStatus int, body string) authHealthProbeDecisionLocal {
	// 判断顺序和外部脚本保持一致：
	// 先看返回体里的 status_code，再看失败信号，最后区分失活还是额度不足。
	httpStatus = normalizeAuthHealthProbeStatusCodeLocal(httpStatus, body)
	failure := extractCliproxyFailureReasonLocal(body, m.oauthHealthProbeMinRemainingWeeklyPercent())
	if httpStatus >= http.StatusBadRequest {
		// 只要 status_code >= 400，就先把这次测活视为失败；
		// 然后再根据 failure 是否属于额度类问题，把结果落到 2 或 3。
		reason := "HTTP " + strconv.Itoa(httpStatus)
		if failure != nil && strings.TrimSpace(failure.Reason) != "" {
			// 如果返回体里已经带了更具体的失败原因，优先展示它，不保留笼统的 HTTP 文案。
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
			// 当测活接口直接返回
			// {"status":503,"detail":"Service Unavailable","message":"Get \"https://chatgpt.com/backend-api/wham/usage\": context deadline exceeded"}
			// 这种结果时，也按状态 3 处理，保留到下一次复检再看，不在这次就判成彻底失活。
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
		// status_code 本身正常时，再看内容里有没有坏信号或额度不足信号。
		status := DBStatusDisabled
		httpStatusForReason := httpStatus
		if failure.QuotaLimited {
			// 额度问题不打成死号，而是落到状态 3，等待后续定时复检恢复。
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

// normalizeAuthHealthProbeStatusCodeLocal 优先取响应体内的 status_code，回退到 HTTP 状态码。
func normalizeAuthHealthProbeStatusCodeLocal(httpStatus int, body string) int {
	// 如果响应体里已经带了 status_code，就以它为准；
	// 这和外部脚本的判断方式保持一致。
	decoded := decodePossibleJSONPayloadLocal(body)
	if data, ok := decoded.(map[string]any); ok {
		if statusCode, okStatus := intValueFromAnyLocal(data["status_code"]); okStatus && statusCode > 0 {
			// 这里优先使用响应体里的 status_code，避免被外层 200 掩盖真实失败。
			return statusCode
		}
	}
	if httpStatus > 0 {
		// 只有响应体没带 status_code 时，才回退到 HTTP 层状态码。
		return httpStatus
	}
	return http.StatusOK
}

// normalizeQuotaHealthProbeStatusCodeLocal 额度不足时把 0 或 200 统一归一成 429，便于后续展示和排查。
func normalizeQuotaHealthProbeStatusCodeLocal(status int) int {
	// 额度不足统一归一成 429，便于后续展示和排查。
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
		// 测活请求本身超时，说明这次没探测成功，后续交给下一次复检。
		return true
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(err.Error())), "context deadline exceeded")
}

func shouldRetryAuthHealthProbeResponseLocal(httpStatus int, body string) bool {
	if httpStatus != http.StatusServiceUnavailable {
		return false
	}
	// 只对 503 + deadline exceeded 这一类临时不可用信号放宽，
	// 让它进入状态 3，等待下一次复检；其他 503 仍按原来的失活逻辑处理。
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
	// 测活请求本身带有 15 秒超时。
	// 如果把同一个 ctx 继续传给落库，前面的 HTTP 探测一旦接近超时，
	// 后面的 SELECT/UPDATE 还没开始就可能直接拿到 context deadline exceeded。
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
		// 先把最新测活结论写回 auth，后面的持久化和调度都以它为准。
		auth.DBStatus = nextDBStatus
		auth.UpdatedAt = now
		switch nextDBStatus {
		case DBStatusActive:
			// 只有从状态 3 恢复到状态 1 时，才清理额度不足留下的运行时痕迹。
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
			// 状态 3 表示账号还活着，但额度不足，不能继续参与请求轮询。
			auth.Disabled = false
			auth.Status = StatusError
			auth.Unavailable = true
			// 这里保留原始原因，方便后续排查到底是“额度耗尽”还是“剩余低于 20%”。
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
			// 状态 3 不依赖冷却时间恢复，而是依赖下一轮定时复检重新判断。
			auth.NextRetryAfter = time.Time{}
			shouldUnregisterClient = true
		case DBStatusDisabled:
			// 状态 2 表示账号失活，后续不再自动复检。
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
			// 状态 2 需要立刻从注册表中移除，避免后续请求继续命中这条账号。
			shouldUnregisterClient = true
		}
		// 每次测活后的最新分类都立刻写库，确保重启后仍按同一结果运行。
		// 这里故意不用测活请求自己的 ctx，避免上游探测快超时时把数据库写入一起带死。
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

// executeAuthHealthProbeLocal 发起一次实际的健康探测请求。
// 这里复用当前 auth 自己的 HttpRequest 能力，保证探测时使用的
// 凭证、代理、请求头和主请求尽量一致。
// 具体“探测哪个地址、用什么方法”由提供方适配层决定，
// 这样后面新增其他提供方时，只需要补自己的 spec 生成逻辑。
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

// supportsAuthHealthProbeLocal 决定某个 auth 当前是否支持本地健康复检。
// 主流程只依赖这个统一入口，不关心具体是哪个提供方。
func supportsAuthHealthProbeLocal(auth *Auth) bool {
	if auth == nil {
		return false
	}
	// 只复检状态 1 和 3；
	// 状态 2 已经是失活账号，不再继续探测。
	switch DBStatusForAuth(auth) {
	case DBStatusDisabled:
		return false
	}
	if isAPIKeyAuth(auth) {
		// 这里的测活规则只针对 OAuth 账号，API key 不走这条 wham/usage 复检链路。
		return false
	}
	_, ok := authHealthProbeSpecForAuthLocal(auth)
	return ok
}

// authHealthProbeSpecForAuthLocal 是多提供方扩展点。
// 当前框架已经支持按 provider 分流，但第一版只挂接了 codex。
// 后面要新增其他提供方时，在这里补一个分支即可。
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

// codexAuthHealthProbeSpecLocal 生成 codex 提供方使用的本地健康复检 spec。
// 这里先把 codex 的探测规则独立出来，后续新增其它 provider 时可以照这个结构继续补。
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
	// 尽量把账号标识一起带上，确保测活打到的就是这条账号自己的上下文。
	if auth.Metadata != nil {
		if accountID, ok := auth.Metadata["account_id"].(string); ok {
			if trimmed := strings.TrimSpace(accountID); trimmed != "" {
				// 优先使用登录时拿到的 account_id，保证测活命中的就是这条账号自己的 usage。
				headers.Set("Chatgpt-Account-Id", trimmed)
			}
		}
	}
	if len(headers.Values("Chatgpt-Account-Id")) == 0 && auth.Attributes != nil {
		if accountID := strings.TrimSpace(auth.Attributes["account_id"]); accountID != "" {
			// 某些来源可能把 account_id 放在 Attributes，这里做一次兜底。
			headers.Set("Chatgpt-Account-Id", accountID)
		}
	}
	return &authHealthProbeSpecLocal{
		Method:  http.MethodGet,
		URL:     baseURL + "/wham/usage",
		Headers: headers,
	}, true
}

// decodePossibleJSONPayloadLocal 尝试把可能是 JSON 字符串的 payload 拆解成结构化对象。
// 有些字段本身是字符串但里面又包了一层 JSON，统一拆开后，后续递归提取失败信号
// 就可以按同一套结构处理。
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
			// 能成功拆成 JSON 时，后面就可以继续递归往里挖失败信号。
			return decoded
		}
		return trimmed
	case []byte:
		return decodePossibleJSONPayloadLocal(string(typed))
	default:
		return payload
	}
}

// extractCliproxyFailureReasonLocal 从测活响应中递归提取失败原因。
// 提取顺序与外部脚本保持一致：error -> rate_limit/code_review_rate_limit -> additional_rate_limits -> 嵌套字段 -> 关键词兜底。
func extractCliproxyFailureReasonLocal(payload any, minRemainingWeeklyPercent int) *authHealthProbeFailureLocal {
	// 按外部脚本的顺序提取失败原因：
	// error -> rate_limit/code_review_rate_limit -> additional_rate_limits -> 嵌套字段 -> 关键词兜底。
	data := decodePossibleJSONPayloadLocal(payload)
	switch typed := data.(type) {
	case string:
		keyword, ok := knownCliproxyKeywordLocal(typed)
		if !ok {
			return nil
		}
		// 纯字符串场景直接按关键词匹配，和外部脚本保持一致。
		return &authHealthProbeFailureLocal{
			Reason:       formatKnownCliproxyErrorLocal(keyword),
			QuotaLimited: isCliproxyQuotaKeywordLocal(keyword),
		}
	case map[string]any:
		errorValue, _ := typed["error"].(map[string]any)
		if errorValue != nil {
			if errType, okType := stringValueFromAnyLocal(errorValue["type"]); okType && strings.TrimSpace(errType) != "" {
				// error.type 是最强信号，命中后直接返回，不再继续往下找。
				return &authHealthProbeFailureLocal{
					Reason:       formatKnownCliproxyErrorLocal(strings.TrimSpace(errType)),
					QuotaLimited: isCliproxyQuotaKeywordLocal(strings.TrimSpace(errType)),
				}
			}
			if errMessage, okMessage := stringValueFromAnyLocal(errorValue["message"]); okMessage && strings.TrimSpace(errMessage) != "" {
				keyword, foundKeyword := knownCliproxyKeywordLocal(errMessage)
				// error.message 没有结构化类型时，至少把原文保留下来，方便后续定位。
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
				// 额外限额也是失效信号的一部分，逐项递归检查。
				if failure := extractRateLimitReasonLocal(rateInfo, key, 0); failure != nil {
					return failure
				}
			}
		case map[string]any:
			for key, rateInfo := range additional {
				// 有些返回是对象形式，这里也要一并覆盖掉。
				if failure := extractRateLimitReasonLocal(rateInfo, "additional_rate_limits."+key, 0); failure != nil {
					return failure
				}
			}
		}

		for _, key := range []string{"data", "body", "response", "text", "content", "status_message"} {
			if failure := extractCliproxyFailureReasonLocal(typed[key], minRemainingWeeklyPercent); failure != nil {
				// 失败信息可能藏在嵌套字段里，这里递归挖出来。
				return failure
			}
		}

		if encoded, errMarshal := json.Marshal(typed); errMarshal == nil {
			if keyword, okKeyword := knownCliproxyKeywordLocal(string(encoded)); okKeyword {
				// 前面都没命中时，再做一次全文关键词兜底。
				return &authHealthProbeFailureLocal{
					Reason:       formatKnownCliproxyErrorLocal(keyword),
					QuotaLimited: isCliproxyQuotaKeywordLocal(keyword),
				}
			}
		}
	}
	return nil
}

// extractRateLimitReasonLocal 从 rate_limit 对象中提取额度不足的具体原因。
func extractRateLimitReasonLocal(rateInfo any, key string, minRemainingWeeklyPercent int) *authHealthProbeFailureLocal {
	// 额度不足的判断分两类：
	// 1. allowed=false 或 limit_reached=true
	// 2. 周额度剩余比例低于阈值（这里固定为 20%）
	data, ok := decodePossibleJSONPayloadLocal(rateInfo).(map[string]any)
	if !ok {
		return nil
	}
	allowed, hasAllowed := boolValueFromAnyLocal(data["allowed"])
	limitReached, hasLimitReached := boolValueFromAnyLocal(data["limit_reached"])
	if (hasAllowed && !allowed) || (hasLimitReached && limitReached) {
		// 一旦明确提示不允许继续用，直接视为额度不足，不再往下看百分比。
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
			// 这里实现你的自定义规则：低于 20% 就进入状态 3。
			return &authHealthProbeFailureLocal{
				Reason:       "weekly quota remaining " + formatPercentLocal(remainingPercent) + "% is below " + strconv.Itoa(minRemainingWeeklyPercent) + "%",
				QuotaLimited: true,
			}
		}
	}
	return nil
}

// extractRemainingPercentLocal 从 primary_window 中提取剩余额度百分比，兼容 remaining_percent 和 used_percent 两种格式。
func extractRemainingPercentLocal(payload any) (float64, bool) {
	// 同时兼容 remaining_percent 和 used_percent 两种格式。
	data, ok := decodePossibleJSONPayloadLocal(payload).(map[string]any)
	if !ok {
		return 0, false
	}
	if remainingPercent, okRemaining := floatValueFromAnyLocal(data["remaining_percent"]); okRemaining {
		// 直接给了 remaining_percent 时，优先使用它。
		return clampPercentLocal(remainingPercent), true
	}
	if usedPercent, okUsed := floatValueFromAnyLocal(data["used_percent"]); okUsed {
		// 只给 used_percent 时，换算成剩余百分比再参与判断。
		return clampPercentLocal(100 - usedPercent), true
	}
	return 0, false
}

// clampPercentLocal 把百分比值限制在 0-100 范围内。
func clampPercentLocal(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

// formatPercentLocal 格式化百分比为可读字符串，去掉尾部多余的 0。
func formatPercentLocal(value float64) string {
	rounded := strconv.FormatFloat(value, 'f', 2, 64)
	rounded = strings.TrimRight(strings.TrimRight(rounded, "0"), ".")
	if rounded == "" {
		return "0"
	}
	return rounded
}

// knownCliproxyKeywordLocal 检查字符串是否包含已知的失败关键词（如 usage_limit_reached、account_deactivated 等）。
func knownCliproxyKeywordLocal(value string) (string, bool) {
	value = strings.ToLower(value)
	for _, keyword := range []string{"usage_limit_reached", "account_deactivated", "insufficient_quota", "invalid_api_key", "unsupported_region"} {
		if strings.Contains(value, keyword) {
			return keyword, true
		}
	}
	return "", false
}

// isCliproxyQuotaKeywordLocal 判断关键词是否属于额度类问题（usage_limit_reached、insufficient_quota）。
func isCliproxyQuotaKeywordLocal(keyword string) bool {
	switch strings.TrimSpace(keyword) {
	case "usage_limit_reached", "insufficient_quota":
		return true
	default:
		return false
	}
}

// formatKnownCliproxyErrorLocal 把已知错误关键词格式化为可读的错误描述，便于写库和排查。
func formatKnownCliproxyErrorLocal(keyword string) string {
	// 给常见错误类型补充更好读的说明，便于写库和排查。
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

// stringValueFromAnyLocal 从任意类型值中提取字符串（支持 string、json.Number）。
func stringValueFromAnyLocal(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case json.Number:
		return typed.String(), true
	}
	return "", false
}

// boolValueFromAnyLocal 从任意类型值中提取布尔值（支持 bool、string、json.Number、float64）。
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

// floatValueFromAnyLocal 从任意类型值中提取浮点数（支持 float32/64、int、int64、json.Number、string）。
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

// intValueFromAnyLocal 从任意类型值中提取整数（支持 int、int32、int64、float64、json.Number、string）。
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

// healthProbeFailureReasonLocal 把测活失败的原因格式化为 JSON 字符串，供落库和展示。
// 如果响应体已经是合法 JSON 则原样返回；否则用 status+detail+message 包一层 JSON 结构。
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

// unauthorizedHealthProbeReasonLocal 生成 401 专用的测活失败原因。
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

func updateAggregatedAvailability(auth *Auth, now time.Time) {
	if auth == nil || len(auth.ModelStates) == 0 {
		return
	}
	allUnavailable := true
	earliestRetry := time.Time{}
	quotaExceeded := false
	quotaRecover := time.Time{}
	maxBackoffLevel := 0
	for _, state := range auth.ModelStates {
		if state == nil {
			continue
		}
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
		auth.NextRetryAfter = now.Add(30 * time.Minute)
	case 402, 403:
		auth.StatusMessage = "payment_required"
		auth.NextRetryAfter = now.Add(30 * time.Minute)
	case 404:
		auth.StatusMessage = "not_found"
		auth.NextRetryAfter = now.Add(12 * time.Hour)
	case 429:
		auth.StatusMessage = "quota exhausted"
		auth.Quota.Exceeded = true
		auth.Quota.Reason = "quota"
		var next time.Time
		if retryAfter != nil {
			next = now.Add(*retryAfter)
		} else {
			cooldown, nextLevel := nextQuotaCooldown(auth.Quota.BackoffLevel, quotaCooldownDisabledForAuth(auth))
			if cooldown > 0 {
				next = now.Add(cooldown)
			}
			auth.Quota.BackoffLevel = nextLevel
		}
		auth.Quota.NextRecoverAt = next
		auth.NextRetryAfter = next
	case 408, 500, 502, 503, 504:
		auth.StatusMessage = "transient upstream error"
		if quotaCooldownDisabledForAuth(auth) {
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

// autoDisableReason 用来判断这次失败是否应该触发“自动停用”。
// 当前规则很简单：外层状态码是 401，且错误内容里也能解析出 status=401，就认为应该自动停用。
func autoDisableReason(resultErr *Error) (string, bool) {
	// 先挡掉非 401 场景，避免把其他错误误判成需要停用。
	if resultErr == nil {
		return "", false
	}

	// 原始错误内容后面还要用于状态记录和展示，所以这里先做一次去空白处理。
	raw := strings.TrimSpace(resultErr.Message)
	if raw == "" {
		return "", false
	}

	// 这里只关心返回体里的 status 字段，不再看其他错误码或文案。
	type providerErrorEnvelope struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}

	var parsed providerErrorEnvelope
	// 只有当错误内容是合法 JSON，并且里面的 status 也是 401，才真正触发自动停用。
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

// disableAuthForPermanentFailure 负责把一个已经确认永久失效的 auth
// 切换成禁用状态，并清掉所有“它还可以稍后再试”的痕迹。
func disableAuthForPermanentFailure(auth *Auth, result Result, reason string, now time.Time) {
	if auth == nil {
		return
	}
	statusMessage := FormatAutoDisabledStatusMessage(reason, now)
	// 先处理 auth 级别状态：
	// - Disabled=true 表示这个 auth 已明确不可再用
	// - Unavailable=false 表示它不是“暂时不可用”，而是“已经下线”
	// - NextRetryAfter/Quota 清空，避免它继续走重试和限额恢复逻辑
	auth.Disabled = true
	auth.Unavailable = false
	auth.Status = StatusDisabled
	auth.StatusMessage = statusMessage
	auth.UpdatedAt = now
	auth.NextRetryAfter = time.Time{}
	auth.Quota = QuotaState{}
	// LastError 继续保留原始错误串，后面数据库保存和前端展示都要用到它。
	auth.LastError = disabledResultError(result.Error, reason)

	if result.Model == "" {
		// 如果这次失败不是某个具体模型触发的，到这里就够了。
		return
	}
	state := ensureModelState(auth, result.Model)
	// 如果这次失败是某个具体模型触发的，
	// 这里再把模型级状态也同步改成禁用，保证 auth 级和模型级显示一致。
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
		// 极端情况下如果拿不到上游错误对象，
		// 就手动补一个兜底错误，避免后续落库和展示时拿不到原因。
		return &Error{Code: "account_deactivated", Message: reason, HTTPStatus: http.StatusUnauthorized}
	}
	cloned := cloneError(resultErr)
	// 尽量补齐错误码和状态码，保证后续状态展示、数据库记录更稳定。
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
		if modelKey != "" && registryRef != nil && !registryRef.ClientSupportsModel(candidate.ID, modelKey) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		m.mu.RUnlock()
		return nil, nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	selected, errPick := m.selector.Pick(ctx, provider, model, opts, candidates)
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
		if modelKey != "" && registryRef != nil && !registryRef.ClientSupportsModel(candidate.ID, modelKey) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		m.mu.RUnlock()
		return nil, nil, "", &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	selected, errPick := m.selector.Pick(ctx, "mixed", model, opts, candidates)
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
	if m.refreshCancel != nil {
		m.refreshCancel()
		m.refreshCancel = nil
	}
	ctx, cancel := context.WithCancel(parent)
	m.refreshCancel = cancel
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		m.checkRefreshes(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.checkRefreshes(ctx)
			}
		}
	}()
}

// StartAutoRefreshLocal 保留原有自动刷新循环，并在本地版流程中额外加入
// OAuth 健康定时巡检。
func (m *Manager) StartAutoRefreshLocal(parent context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = refreshCheckInterval
	}
	if m.refreshCancel != nil {
		m.refreshCancel()
		m.refreshCancel = nil
	}
	ctx, cancel := context.WithCancel(parent)
	m.refreshCancel = cancel
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		// 启动时先跑一轮：既做原有 refresh，也做本地健康巡检。
		m.checkRefreshes(ctx)
		m.checkAuthHealthProbesLocal(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// 后续每个周期同时执行两件事：
				// 1. 原有的 token 自动刷新；
				// 2. 本地定时健康复检。
				m.checkRefreshes(ctx)
				m.checkAuthHealthProbesLocal(ctx)
			}
		}
	}()
}

// StopAutoRefresh cancels the background refresh loop, if running.
func (m *Manager) StopAutoRefresh() {
	if m.refreshCancel != nil {
		m.refreshCancel()
		m.refreshCancel = nil
	}
}

func (m *Manager) checkRefreshes(ctx context.Context) {
	// log.Debugf("checking refreshes")
	now := time.Now()
	snapshot := m.snapshotAuths()
	for _, a := range snapshot {
		typ, _ := a.AccountInfo()
		if typ != "api_key" {
			if !m.shouldRefresh(a, now) {
				continue
			}
			log.Debugf("checking refresh for %s, %s, %s", a.Provider, a.ID, typ)

			if exec := m.executorFor(a.Provider); exec == nil {
				continue
			}
			if !m.markRefreshPending(a.ID, now) {
				continue
			}
			go m.refreshAuthWithLimit(ctx, a.ID)
		}
	}
}

func (m *Manager) refreshAuthWithLimit(ctx context.Context, id string) {
	if m.refreshSemaphore == nil {
		m.refreshAuth(ctx, id)
		return
	}
	select {
	case m.refreshSemaphore <- struct{}{}:
		defer func() { <-m.refreshSemaphore }()
	case <-ctx.Done():
		return
	}
	m.refreshAuth(ctx, id)
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
	defer m.mu.Unlock()
	auth, ok := m.auths[id]
	if !ok || auth == nil || auth.Disabled {
		return false
	}
	if !auth.NextRefreshAfter.IsZero() && now.Before(auth.NextRefreshAfter) {
		return false
	}
	auth.NextRefreshAfter = now.Add(refreshPendingBackoff)
	m.auths[id] = auth
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
		m.mu.Lock()
		if current := m.auths[id]; current != nil {
			current.NextRefreshAfter = now.Add(refreshFailureBackoff)
			current.LastError = &Error{Message: err.Error()}
			m.auths[id] = current
			if m.scheduler != nil {
				m.scheduler.upsertAuth(current.Clone())
			}
		}
		m.mu.Unlock()
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
