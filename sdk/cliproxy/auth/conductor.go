package auth

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// ProviderExecutor 定义 Manager 执行提供商调用所需的契约接口。
type ProviderExecutor interface {
	// Identifier 返回此执行器处理的提供商标识键。
	Identifier() string
	// Execute 处理非流式执行并返回提供商响应数据。
	Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error)
	// ExecuteStream 处理流式执行并返回包含上游响应头和提供商数据块通道的 StreamResult。
	ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error)
	// Refresh 尝试刷新提供商凭证并返回更新后的认证状态。
	Refresh(ctx context.Context, auth *Auth) (*Auth, error)
	// CountTokens 返回给定请求的令牌数量。
	CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error)
	// HttpRequest 向给定的 HTTP 请求注入提供商凭证并执行请求。调用者在响应非空时必须关闭响应体。
	HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error)
}

// RequestAuthPreparer lets an executor update missing auth metadata immediately
// before a request. Manager serializes and persists returned updates.
type RequestAuthPreparer interface {
	ShouldPrepareRequestAuth(auth *Auth) bool
	PrepareRequestAuth(ctx context.Context, auth *Auth) (*Auth, error)
}

// ExecutionSessionCloser allows executors to release per-session runtime resources.

type ExecutionSessionCloser interface {
	CloseExecutionSession(sessionID string)
}

const (
	homeAuthCountMetadataKey = "__cliproxy_home_auth_count"
	// CloseAllExecutionSessionsID asks an executor to release all active execution sessions.
	// Executors that do not support this marker may ignore it.

	CloseAllExecutionSessionsID = "__all_execution_sessions__"
)

// RefreshEvaluator 允许运行时状态覆盖刷新决策。
type RefreshEvaluator interface {
	ShouldRefresh(now time.Time, auth *Auth) bool
}

const (
	refreshCheckInterval                     = 10 * time.Minute // 无任何刷新信息时的最后兜底
	refreshMaxConcurrency                    = 16
	refreshPendingBackoff                    = time.Minute
	refreshFailureBackoff                    = 5 * time.Minute
	refreshIneffectiveBackoff                = 30 * time.Second
	healthProbeTimeout                       = 15 * time.Second
	healthProbeMaxGap                        = 2 * time.Minute
	healthProbeMaxWorkers                    = internalconfig.DefaultOAuthHealthProbeMaxWorkers
	quotaBackoffBase                         = time.Second
	quotaBackoffMax                          = 30 * time.Minute
	healthProbeMinimumRemainingWeeklyPercent = 90
	codexHealthProbeUserAgent                = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
	healthProbePersistTimeout                = 5 * time.Second
)

// Result 捕获执行结果，用于调整认证状态。
type Result struct {
	// AuthID 引用产生此结果的认证条目。
	AuthID string
	// Provider 为方便触发钩子而复制的提供商标识。
	Provider string
	// Model 是请求中使用的上游模型标识符。
	Model string
	// Success 标记执行是否成功。
	Success bool
	// RetryAfter 携带提供商提供的重试提示（如 429 retryDelay）。
	RetryAfter *time.Duration
	// Error 在 Success 为 false 时描述失败原因。
	Error *Error
}

// Selector 为执行选择一个认证候选者。
type Selector interface {
	Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error)
}

// Hook 捕获生命周期回调，用于观察认证状态变更。
type PluginScheduler interface {
	PickAuth(context.Context, pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickResponse, bool, error)
}

type pluginSchedulerState interface {
	HasScheduler() bool
}

// StoppableSelector is an optional interface for selectors that hold resources.
// Selectors that implement this interface will have Stop called during shutdown.
type StoppableSelector interface {
	Selector
	Stop()
}

// Hook captures lifecycle callbacks for observing auth changes.
type Hook interface {
	// OnAuthRegistered 在新认证注册时触发。
	OnAuthRegistered(ctx context.Context, auth *Auth)
	// OnAuthUpdated 在已有认证状态变更时触发。
	OnAuthUpdated(ctx context.Context, auth *Auth)
	// OnResult 在记录执行结果时触发。
	OnResult(ctx context.Context, result Result)
}

// NoopHook 提供可选的钩子默认实现。
type NoopHook struct{}

// OnAuthRegistered 实现 Hook 接口。
func (NoopHook) OnAuthRegistered(context.Context, *Auth) {}

// OnAuthUpdated 实现 Hook 接口。
func (NoopHook) OnAuthUpdated(context.Context, *Auth) {}

// OnResult 实现 Hook 接口。
func (NoopHook) OnResult(context.Context, Result) {}

// Manager 编排认证生命周期、选择、执行和持久化。
type Manager struct {
	store         Store
	cooldownStore CooldownStateStore
	executors     map[string]ProviderExecutor
	selector      Selector
	hook          Hook
	mu            sync.RWMutex
	auths         map[string]*Auth

	// inactiveAuths keeps non-routable auth snapshots so their state remains queryable.
	inactiveAuths map[string]*Auth
	scheduler     *authScheduler
	// pluginScheduler runs outside m.mu before falling back to native selection.
	pluginScheduler PluginScheduler
	// homeRuntimeAuths caches auths returned by Home so websocket sessions can
	// reuse an established upstream credential without dispatching every turn.
	homeRuntimeAuths map[string]map[string]*Auth
	// providerOffsets tracks per-model provider rotation state for multi-provider routing.

	providerOffsets map[string]int

	// Retry 控制请求重试行为。
	requestRetry        atomic.Int32
	maxRetryCredentials atomic.Int32
	maxRetryInterval    atomic.Int64

	// oauthModelAlias 存储全局 OAuth 模型别名映射（别名 -> 上游名称），按键值通道索引。
	oauthModelAlias atomic.Value

	// apiKeyModelAlias 缓存 API 密钥认证已解析的模型别名映射。
	// 以 auth.ID 为键，值为 alias(小写) -> 上游模型（包含后缀）。
	apiKeyModelAlias atomic.Value

	// modelPoolOffsets 跟踪每个认证的别名池轮转状态。
	modelPoolOffsets map[string]int

	// runtimeConfig 存储最新的应用配置，用于请求时决策。
	// 在 NewManager 中初始化；首次 Store() 之前不可调用 Load()。
	runtimeConfig atomic.Value

	// 由宿主注入的可选 HTTP RoundTripper 提供器。
	rtProvider RoundTripperProvider

	// Auto refresh state
	refreshCancel   context.CancelFunc
	refreshLoop     *authAutoRefreshLoop
	healthSemaphore atomic.Value
	healthProbeAt   sync.Map
	healthProbeBusy sync.Map

	requestPrepareLocks sync.Map
	// refreshLocks serializes credential refresh per auth ID so concurrent
	// 401 recoveries and auto-refresh workers do not race the same refresh_token.
	refreshLocks sync.Map
}

// NewManager 使用可选的自定义选择器和钩子构造管理器。
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

// HomeEnabled reports whether the home control plane integration is enabled in the runtime config.
func (m *Manager) HomeEnabled() bool {
	if m == nil {
		return false
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	return cfg != nil && cfg.Home.Enabled
}

// RoundTripperProvider 定义了每个认证的 HTTP 传输层的最小提供器接口。
type RoundTripperProvider interface {
	RoundTripperFor(auth *Auth) http.RoundTripper
}
