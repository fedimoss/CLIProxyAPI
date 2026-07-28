package auth

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

var quotaCooldownDisabled atomic.Bool

// SetQuotaCooldownDisabled 全局切换配额冷却调度开关。
func SetQuotaCooldownDisabled(disable bool) {
	quotaCooldownDisabled.Store(disable)
}

func quotaCooldownDisabledForAuth(auth *Auth) bool {
	return quotaCooldownDisabledForAuthWithConfig(auth, nil)
}

func quotaCooldownDisabledForAuthWithConfig(auth *Auth, cfg *internalconfig.Config) bool {
	if auth != nil {
		if override, ok := auth.DisableCoolingOverride(); ok {
			return override
		}
		if providerCoolingDisabledForAuth(auth, cfg) {
			return true
		}
	}
	if cfg != nil && cfg.DisableCooling {
		return true
	}
	return quotaCooldownDisabled.Load()
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
		providerKey := executorKeyFromAuth(auth)
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
		providerKey := executorKeyFromAuth(auth)
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

// cooldownWaitJitterCap bounds the random jitter added to cooldown waits so a
// long wait is never extended by more than this amount.
const cooldownWaitJitterCap = 2 * time.Second

// jitteredCooldownWait adds a small random delay to a cooldown wait so
// concurrent requests waiting on the same recovery deadline do not wake in
// lockstep and stampede the first credential that recovers. The jitter never
// pushes the total wait past maxWait, which callers have already enforced as
// the retry ceiling; maxWait <= 0 means no ceiling.
func jitteredCooldownWait(wait, maxWait time.Duration) time.Duration {
	if wait <= 0 {
		return wait
	}
	jitterRange := wait / 4
	if jitterRange > cooldownWaitJitterCap {
		jitterRange = cooldownWaitJitterCap
	}
	if maxWait > 0 && jitterRange > maxWait-wait {
		jitterRange = maxWait - wait
	}
	if jitterRange <= 0 {
		return wait
	}
	return wait + rand.N(jitterRange)
}

func waitForCooldown(ctx context.Context, wait, maxWait time.Duration) error {
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(jitteredCooldownWait(wait, maxWait))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// MarkResult 记录执行结果并通知钩子。
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
	cooldownStateChanged := false

	m.mu.Lock()
	if auth, ok := m.authByIDLocked(result.AuthID); ok && auth != nil {
		now := time.Now()
		var cooldownRecordsBefore []CooldownStateRecord
		trackCooldownState := m.cooldownStore != nil
		if trackCooldownState {
			cooldownRecordsBefore = m.cooldownStateRecordsForAuthLocked(auth, now)
		}
		auth.recordRecentRequest(now, result.Success)
		if result.Success {
			auth.Success++
		} else {
			auth.Failed++
		}

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
			// ── MarkResult 路径：配额耗尽检测 ──
			// 判断条件：响应中包含 "type":"usage_limit_reached" 且 resets_in_seconds > 1800（30分钟）。
			// 响应示例：{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached",
			//   "plan_type":"plus","resets_at":1776326990,"resets_in_seconds":86400}}
			// 命中后将账号标记为配额受限（状态3），从内存中取消注册，等待定时健康探测复检恢复。
			// 注意：此处只处理 type 为 "usage_limit_reached" 字符串的错误格式，不涉及布尔值 usage_limit_reached。
			if isUsageLimitReachedShortResetResultError(result.Error) {
				quotaReason := "quota exhausted (usage_limit_reached)"
				failure := extractCliproxyFailureReasonLocal(result.Error.Message, m.oauthHealthProbeMinRemainingWeeklyPercent())
				if failure != nil && strings.TrimSpace(failure.Reason) != "" {
					quotaReason = strings.TrimSpace(failure.Reason)
				}
				applyAuthQuotaLimitedState(auth, result, quotaReason, now)
				_ = m.persist(ctx, auth)
				authSnapshot = auth.Clone()
				shouldUnregisterClient = true
			} else if reason, okDisable := autoDisableReason(result.Error); okDisable {
				// 401 未授权错误：区分配额受限和账号失活两种情况。
				failure := extractCliproxyFailureReasonLocal(result.Error.Message, m.oauthHealthProbeMinRemainingWeeklyPercent())
				if failure != nil && failure.QuotaLimited {
					quotaReason := reason
					if failure.Reason != "" {
						quotaReason = failure.Reason
					}
					applyAuthQuotaLimitedState(auth, result, quotaReason, now)
				} else {
					disableAuthForPermanentFailure(auth, result, reason, now)
				}
				_ = m.persist(ctx, auth)
				authSnapshot = auth.Clone()
				shouldUnregisterClient = true
			} else if result.Model != "" {
				if !isRequestScopedResultError(result.Error) {
					disableCooling := m.cooldownDisabledForAuth(auth)
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
					} else if isCloudflareChallengeResultError(result.Error) {
						next, backoffLevel := nextCloudflareCooldown(state.Quota.BackoffLevel, disableCooling, now)
						state.NextRetryAfter = next
						state.StatusMessage = "cloudflare challenge"
						if auth.LastError != nil {
							auth.StatusMessage = "cloudflare challenge"
						}
						state.Quota = QuotaState{
							Exceeded:      true,
							Reason:        "cloudflare challenge",
							NextRecoverAt: next,
							BackoffLevel:  backoffLevel,
						}
					} else if isInvalidGrantResultError(result.Error) {
						if disableCooling {
							state.NextRetryAfter = time.Time{}
						} else {
							state.NextRetryAfter = now.Add(30 * time.Minute)
							suspendReason = "invalid_grant"
							shouldSuspendModel = true
						}
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
									next, backoffLevel = quotaCooldownAfterFailure(state.Quota, now)
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
								state.NextRetryAfter = nextTransientErrorRetryAfter(now)
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
				disableCooling := m.cooldownDisabledForAuth(auth)
				applyAuthFailureState(auth, result.Error, result.RetryAfter, now, disableCooling)
			}
		}

		m.storeAuthLocked(auth)
		if !shouldUnregisterClient {
			_ = m.persist(ctx, auth)
			authSnapshot = auth.Clone()
		}
		if trackCooldownState {
			cooldownRecordsAfter := m.cooldownStateRecordsForAuthLocked(auth, now)
			cooldownStateChanged = !cooldownStateRecordsEqual(cooldownRecordsBefore, cooldownRecordsAfter)
		}
	}
	m.mu.Unlock()
	if shouldUnregisterClient {
		registry.GetGlobalRegistry().UnregisterClient(result.AuthID)
	}
	if m.scheduler != nil && authSnapshot != nil {
		m.scheduler.upsertAuth(authSnapshot)
	}
	if authSnapshot != nil && cooldownStateChanged {
		m.persistCooldownStates(context.Background())
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
	m.publishErrorEvent(result, authSnapshot)
}

func (m *Manager) recordAvailabilityNeutralResult(ctx context.Context, result Result) {
	if result.AuthID == "" {
		return
	}

	var authSnapshot *Auth
	m.mu.Lock()
	if auth, ok := m.auths[result.AuthID]; ok && auth != nil {
		now := time.Now()
		auth.recordRecentRequest(now, result.Success)
		if result.Success {
			auth.Success++
		} else {
			auth.Failed++
		}
		_ = m.persist(ctx, auth)
		authSnapshot = auth.Clone()
	}
	m.mu.Unlock()

	m.hook.OnResult(ctx, result)
	m.publishErrorEvent(result, authSnapshot)
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

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
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

func isRequestScopedError(err error) bool {
	if err == nil {
		return false
	}
	requestErr, ok := errors.AsType[cliproxyexecutor.RequestScopedError](err)
	return ok && requestErr != nil && requestErr.IsRequestScoped()
}

func resultErrorFromError(err error) *Error {
	if err == nil {
		return nil
	}
	var sourceErr *Error
	var resultErr *Error
	if errors.As(err, &sourceErr) && sourceErr != nil {
		resultErr = cloneError(sourceErr)
	} else {
		resultErr = &Error{Message: err.Error()}
	}
	if resultErr.HTTPStatus == 0 {
		resultErr.HTTPStatus = statusCodeFromError(err)
	}
	if isRequestScopedError(err) || isRequestInvalidError(err) {
		resultErr.Code = requestScopedErrorCode
	}
	return resultErr
}

func isUnauthorizedError(err error) bool {
	if err == nil {
		return false
	}
	if statusCodeFromError(err) == http.StatusUnauthorized {
		return true
	}
	raw := strings.ToLower(err.Error())
	return strings.Contains(raw, "status 401") || strings.Contains(raw, "401 unauthorized")
}

func hasUnauthorizedAuthFailure(auth *Auth) bool {
	if auth == nil || auth.LastError == nil {
		return false
	}
	return auth.LastError.StatusCode() == http.StatusUnauthorized || strings.EqualFold(auth.LastError.Code, "unauthorized")
}

func refreshErrorFromError(err error) *Error {
	if err == nil {
		return nil
	}
	statusCode := statusCodeFromError(err)
	if statusCode == 0 && isUnauthorizedError(err) {
		statusCode = http.StatusUnauthorized
	}
	authErr := &Error{Message: err.Error(), HTTPStatus: statusCode}
	if statusCode == http.StatusUnauthorized {
		authErr.Code = "unauthorized"
		authErr.Retryable = false
	}
	return authErr
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
	// retryAfter 是变量不是类型。应该直接返回指针
	return retryAfter
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

func isInvalidGrantErrorMessage(message string) bool {
	return strings.Contains(strings.ToLower(message), "invalid_grant")
}

func isInvalidGrantError(err error) bool {
	if err == nil {
		return false
	}
	status := statusCodeFromError(err)
	if status != http.StatusBadRequest && status != http.StatusUnauthorized {
		return false
	}
	return isInvalidGrantErrorMessage(err.Error())
}

func isInvalidGrantResultError(err *Error) bool {
	if err == nil {
		return false
	}
	status := statusCodeFromResult(err)
	if status != http.StatusBadRequest && status != http.StatusUnauthorized {
		return false
	}
	return isInvalidGrantErrorMessage(err.Code) || isInvalidGrantErrorMessage(err.Message)
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

func isCloudflareChallengeErrorMessage(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	return strings.Contains(lower, "challenge-platform") ||
		strings.Contains(lower, "cf-mitigated") ||
		strings.Contains(lower, "cloudflare challenge") ||
		(strings.Contains(lower, "cloudflare") && strings.Contains(lower, "<html"))
}

func isCloudflareChallengeError(err error) bool {
	if err == nil {
		return false
	}
	return isCloudflareChallengeErrorMessage(err.Error())
}

func isCloudflareChallengeResultError(err *Error) bool {
	if err == nil {
		return false
	}
	return isCloudflareChallengeErrorMessage(err.Message)
}

func nextCloudflareCooldown(backoffLevel int, disableCooling bool, now time.Time) (time.Time, int) {
	var next time.Time
	if !disableCooling {
		cooldown, nextLevel := nextQuotaCooldown(backoffLevel, disableCooling)
		if cooldown < 10*time.Second {
			cooldown = 10 * time.Second
		}
		if cooldown > 0 {
			next = now.Add(cooldown)
		}
		backoffLevel = nextLevel
	}
	return next, backoffLevel
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

func isRequestScopedResultError(err *Error) bool {
	return err != nil && (err.IsRequestScoped() || isRequestScopedNotFoundResultError(err))
}

func isCountTokensEndpointNotFoundError(err error, requestedModel string) bool {
	if err == nil || statusCodeFromError(err) != http.StatusNotFound {
		return false
	}
	baseModel := thinking.ParseSuffix(requestedModel).ModelName
	return !isExplicitModelNotFoundError(err, baseModel)
}

func isExplicitModelNotFoundError(err error, requestedModel string) bool {
	if err == nil {
		return false
	}
	if authErr, ok := err.(*Error); ok && authErr != nil {
		if isModelNotFoundIdentifier(authErr.Code) || isStructuredModelNotFoundError(authErr.Message, requestedModel) {
			return true
		}
	} else if isStructuredModelNotFoundError(err.Error(), requestedModel) {
		return true
	}

	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		for _, nested := range wrapped.Unwrap() {
			if isExplicitModelNotFoundError(nested, requestedModel) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return isExplicitModelNotFoundError(wrapped.Unwrap(), requestedModel)
	}
	return false
}

func isStructuredModelNotFoundError(message, requestedModel string) bool {
	var payload any
	if errJSON := json.Unmarshal([]byte(strings.TrimSpace(message)), &payload); errJSON != nil {
		return false
	}
	return containsStructuredModelNotFound(payload, requestedModel)
}

func containsStructuredModelNotFound(value any, requestedModel string) bool {
	switch typed := value.(type) {
	case map[string]any:
		notFoundType := false
		exactModelReference := false
		for key, item := range typed {
			text, isString := item.(string)
			if isString {
				switch strings.ToLower(strings.TrimSpace(key)) {
				case "code":
					if isModelNotFoundIdentifier(text) {
						return true
					}
				case "type":
					if isModelNotFoundIdentifier(text) {
						return true
					}
					notFoundType = notFoundType || isNotFoundErrorIdentifier(text)
				case "error", "message", "detail", "error_description", "title":
					if isExplicitModelNotFoundMessage(text, requestedModel) {
						return true
					}
					exactModelReference = exactModelReference || isExactRequestedModelReference(text, requestedModel)
				}
			}
			switch item.(type) {
			case map[string]any, []any:
				if containsStructuredModelNotFound(item, requestedModel) {
					return true
				}
			}
		}
		return notFoundType && exactModelReference
	case []any:
		for _, item := range typed {
			if text, isString := item.(string); isString && isExplicitModelNotFoundMessage(text, requestedModel) {
				return true
			}
			if containsStructuredModelNotFound(item, requestedModel) {
				return true
			}
		}
	}
	return false
}

func isModelNotFoundIdentifier(value string) bool {
	candidate := strings.ToLower(strings.TrimSpace(value))
	if fragment := strings.LastIndex(candidate, "#"); fragment >= 0 && fragment+1 < len(candidate) {
		candidate = candidate[fragment+1:]
	} else {
		if query := strings.Index(candidate, "?"); query >= 0 {
			candidate = candidate[:query]
		}
		candidate = strings.TrimRight(candidate, "/")
		if separator := strings.LastIndexAny(candidate, "/:"); separator >= 0 {
			candidate = candidate[separator+1:]
		}
	}
	normalized := strings.NewReplacer("-", "_", " ", "_").Replace(candidate)
	switch normalized {
	case "model_not_found", "model_not_found_error", "unknown_model", "model_does_not_exist", "model_not_exist":
		return true
	default:
		return false
	}
}

func isNotFoundErrorIdentifier(value string) bool {
	normalized := strings.NewReplacer("-", "_", " ", "_").Replace(strings.ToLower(strings.TrimSpace(value)))
	return normalized == "not_found" || normalized == "not_found_error"
}

func isExplicitModelNotFoundMessage(message, requestedModel string) bool {
	lower := strings.Trim(strings.ToLower(strings.TrimSpace(message)), " .!;\t\r\n")
	if lower == "" {
		return false
	}
	normalized := strings.NewReplacer("-", "_", " ", "_").Replace(lower)
	if strings.Contains(normalized, "model_not_found") || strings.Contains(normalized, "unknown_model") {
		return true
	}
	for _, prefix := range []string{"no such model", "unknown model"} {
		if lower != prefix && !strings.HasPrefix(lower, prefix+" ") && !strings.HasPrefix(lower, prefix+":") {
			continue
		}
		remainder := strings.TrimSpace(strings.TrimPrefix(lower, prefix))
		remainder = strings.TrimSpace(strings.TrimPrefix(remainder, ":"))
		if remainder == "" {
			return true
		}
		missingSuffix, matches := trimRequestedModelReference(remainder, requestedModel)
		return matches && missingSuffix == ""
	}
	for _, prefix := range []string{"the requested model", "requested model", "the model", "model"} {
		if lower != prefix && !strings.HasPrefix(lower, prefix+" ") && !strings.HasPrefix(lower, prefix+":") {
			continue
		}
		remainder := strings.TrimSpace(strings.TrimPrefix(lower, prefix))
		remainder = strings.TrimSpace(strings.TrimPrefix(remainder, ":"))
		if isMissingModelPhrase(remainder) {
			return true
		}
		missingSuffix, matches := trimRequestedModelReference(remainder, requestedModel)
		return matches && isMissingModelPhrase(missingSuffix)
	}
	return false
}

func isExactRequestedModelReference(message, requestedModel string) bool {
	lower := strings.Trim(strings.ToLower(strings.TrimSpace(message)), " .!;\t\r\n")
	for _, prefix := range []string{"the requested model", "requested model", "the model", "model"} {
		if lower != prefix && !strings.HasPrefix(lower, prefix+" ") && !strings.HasPrefix(lower, prefix+":") {
			continue
		}
		remainder := strings.TrimSpace(strings.TrimPrefix(lower, prefix))
		remainder = strings.TrimSpace(strings.TrimPrefix(remainder, ":"))
		suffix, matches := trimRequestedModelReference(remainder, requestedModel)
		return matches && suffix == ""
	}
	return false
}

func trimRequestedModelReference(value, requestedModel string) (string, bool) {
	model := strings.ToLower(strings.TrimSpace(requestedModel))
	if model == "" {
		return "", false
	}
	for _, candidate := range []string{model, "'" + model + "'", `"` + model + `"`, "`" + model + "`"} {
		if value == candidate {
			return "", true
		}
		if !strings.HasPrefix(value, candidate) {
			continue
		}
		remainder := value[len(candidate):]
		if remainder == "" || strings.ContainsRune(" :,", rune(remainder[0])) {
			return strings.TrimLeft(remainder, " :,"), true
		}
	}
	return "", false
}

func isMissingModelPhrase(value string) bool {
	switch strings.Trim(value, " .!;\t\r\n") {
	case "not found", "was not found", "could not be found", "does not exist", "doesn't exist", "not exist", "is unknown":
		return true
	default:
		return false
	}
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
	if isRequestScopedError(err) {
		return true
	}
	if isCloudflareChallengeError(err) {
		return false
	}
	if isInvalidGrantError(err) {
		return false
	}
	if isModelSupportError(err) {
		return false
	}
	status := statusCodeFromError(err)
	switch status {
	case http.StatusBadRequest:
		msg := err.Error()
		return strings.Contains(msg, "invalid_request_error") ||
			strings.Contains(msg, "bad_request_error") ||
			strings.Contains(msg, "INVALID_ARGUMENT") ||
			strings.Contains(msg, "FAILED_PRECONDITION")
	case http.StatusNotFound:
		return isRequestScopedNotFoundMessage(err.Error())
	case http.StatusUnprocessableEntity:
		return true
	case http.StatusInternalServerError:
		msg := err.Error()
		return strings.Contains(msg, "\"status\":\"UNKNOWN\"") ||
			strings.Contains(msg, "\"status\": \"UNKNOWN\"")
	default:
		return false
	}
}

func applyAuthFailureState(auth *Auth, resultErr *Error, retryAfter *time.Duration, now time.Time, disableCooling bool) {
	if auth == nil {
		return
	}
	if isRequestScopedResultError(resultErr) {
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
	if isCloudflareChallengeResultError(resultErr) {
		auth.StatusMessage = "cloudflare challenge"
		next, backoffLevel := nextCloudflareCooldown(auth.Quota.BackoffLevel, disableCooling, now)
		auth.Quota = QuotaState{
			Exceeded:      true,
			Reason:        "cloudflare challenge",
			NextRecoverAt: next,
			BackoffLevel:  backoffLevel,
		}
		auth.NextRetryAfter = next
		return
	}
	if isInvalidGrantResultError(resultErr) {
		auth.StatusMessage = "invalid_grant"
		if disableCooling {
			auth.NextRetryAfter = time.Time{}
		} else {
			auth.NextRetryAfter = now.Add(30 * time.Minute)
		}
		return
	}
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
				next, auth.Quota.BackoffLevel = quotaCooldownAfterFailure(auth.Quota, now)
			}
		}
		auth.Quota.NextRecoverAt = next
		auth.NextRetryAfter = next
	case 408, 500, 502, 503, 504:
		auth.StatusMessage = "transient upstream error"
		if disableCooling {
			auth.NextRetryAfter = time.Time{}
		} else {
			auth.NextRetryAfter = nextTransientErrorRetryAfter(now)
		}
	default:
		if auth.StatusMessage == "" {
			auth.StatusMessage = "request failed"
		}
	}
}
func autoDisableReason(resultErr *Error) (string, bool) {
	if resultErr == nil {
		return "", false
	}
	raw := strings.TrimSpace(resultErr.Message)
	if raw == "" {
		return "", false
	}
	type providerErrorEnvelope struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}

	var parsed providerErrorEnvelope
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
func disableAuthForPermanentFailure(auth *Auth, result Result, reason string, now time.Time) {
	if auth == nil {
		return
	}
	statusMessage := FormatAutoDisabledStatusMessage(reason, now)
	auth.DBStatus = DBStatusDisabled
	auth.Disabled = true
	auth.Unavailable = false
	auth.Status = StatusDisabled
	auth.StatusMessage = statusMessage
	auth.UpdatedAt = now
	auth.NextRetryAfter = time.Time{}
	auth.Quota = QuotaState{}
	auth.LastError = disabledResultError(result.Error, reason)

	if result.Model == "" {
		return
	}
	state := ensureModelState(auth, result.Model)
	state.Status = StatusDisabled
	state.StatusMessage = statusMessage
	state.Unavailable = false
	state.NextRetryAfter = time.Time{}
	state.Quota = QuotaState{}
	state.UpdatedAt = now
	state.LastError = disabledResultError(result.Error, reason)
}

// applyAuthQuotaLimitedState 将认证标记为配额受限状态（DBStatus=QuotaLimited）。
// 配额受限的账号不会被选号路由，但定时健康探测会持续复检，额度恢复后自动重新激活。
func applyAuthQuotaLimitedState(auth *Auth, result Result, reason string, now time.Time) {
	if auth == nil {
		return
	}
	auth.DBStatus = DBStatusQuotaLimited
	auth.Disabled = false
	auth.Unavailable = true
	auth.Status = StatusError
	auth.StatusMessage = strings.TrimSpace(reason)
	auth.UpdatedAt = now
	auth.Quota = QuotaState{Exceeded: true, Reason: "quota"}
	if result.Error != nil {
		auth.LastError = &Error{
			Code:       "quota_limited",
			Message:    strings.TrimSpace(reason),
			HTTPStatus: result.Error.HTTPStatus,
		}
	}
	if result.Model == "" {
		return
	}
	state := ensureModelState(auth, result.Model)
	state.Status = StatusError
	state.StatusMessage = strings.TrimSpace(reason)
	state.Unavailable = true
	state.UpdatedAt = now
}

// isUsageLimitReachedShortResetResultError 判断错误是否为配额耗尽（type="usage_limit_reached" 且 resets_in_seconds > 1800）。
// 用于 MarkResult 路径：当 OAuth 账号请求返回包含 usage_limit_reached 错误且重置时间超过30分钟时，
// 将其标记为配额受限（状态3）而非账号失活，等待定时健康探测复检恢复。
// 响应格式示例：{"error":{"type":"usage_limit_reached","resets_in_seconds":86400}}
func isUsageLimitReachedShortResetResultError(resultErr *Error) bool {
	if resultErr == nil {
		return false
	}
	raw := strings.TrimSpace(resultErr.Message)
	if raw == "" {
		return false
	}
	decoded := decodePossibleJSONPayloadLocal(raw)
	data, ok := decoded.(map[string]any)
	if !ok {
		return false
	}
	if hasUsageLimitReachedShortResetFields(data) {
		return true
	}
	errorData, ok := decodePossibleJSONPayloadLocal(data["error"]).(map[string]any)
	if !ok {
		return false
	}
	return hasUsageLimitReachedShortResetFields(errorData)
}

// hasUsageLimitReachedShortResetFields 检查 JSON 数据中 type 是否为 "usage_limit_reached"（字符串）且 resets_in_seconds > 1800（30分钟）。
// 仅用于 MarkResult 路径，处理错误响应格式。
func hasUsageLimitReachedShortResetFields(data map[string]any) bool {
	if len(data) == 0 {
		return false
	}
	errType, okType := stringValueFromAnyLocal(data["type"])
	if !okType || !strings.EqualFold(strings.TrimSpace(errType), "usage_limit_reached") {
		return false
	}
	resetsInSeconds, _ := intValueFromAnyLocal(data["resets_in_seconds"])
	return resetsInSeconds > 1800
}

func disabledResultError(resultErr *Error, reason string) *Error {
	if resultErr == nil {
		return &Error{Code: "account_deactivated", Message: reason, HTTPStatus: http.StatusUnauthorized}
	}
	cloned := cloneError(resultErr)
	if strings.TrimSpace(cloned.Code) == "" {
		cloned.Code = "account_deactivated"
	}
	if cloned.HTTPStatus == 0 {
		cloned.HTTPStatus = http.StatusUnauthorized
	}
	return cloned
}

// quotaCooldownAfterFailure returns the recovery deadline and backoff level for
// a quota failure observed at now. Failures that land while a previous quota
// window is still open reuse that window instead of escalating, so a burst of
// concurrent in-flight failures advances the backoff ladder at most once per
// window.
func quotaCooldownAfterFailure(quota QuotaState, now time.Time) (time.Time, int) {
	if quota.NextRecoverAt.After(now) {
		return quota.NextRecoverAt, quota.BackoffLevel
	}
	cooldown, nextLevel := nextQuotaCooldown(quota.BackoffLevel, false)
	var next time.Time
	if cooldown > 0 {
		next = now.Add(cooldown)
	}
	return next, nextLevel
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
