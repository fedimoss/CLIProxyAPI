package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	log "github.com/sirupsen/logrus"
)

// MarkResultLocal records execution results for auth state updates.
// Health probes are triggered only by the periodic scheduler.
func (m *Manager) MarkResultLocal(ctx context.Context, result Result) {
	m.MarkResult(ctx, result)
}

// authHealthProbeSpecLocal 定义健康探测的请求规格，包括方法、URL和请求头。
type authHealthProbeSpecLocal struct {
	Method  string
	URL     string
	Headers http.Header
}

// authHealthProbeFailureLocal 表示健康探测失败的原因及是否为配额限制。
type authHealthProbeFailureLocal struct {
	Reason       string
	QuotaLimited bool
}

// authHealthProbeDecisionLocal 表示健康探测的决策结果，包含数据库状态、HTTP状态码和原因。
type authHealthProbeDecisionLocal struct {
	DBStatus   int
	HTTPStatus int
	Reason     string
}

// checkAuthHealthProbesLocal 检查所有支持健康探测的认证，批量启动探测。
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
		log.Infof("oauth health probe started")
	}
	for _, auth := range pending {
		go m.runAuthHealthProbeWithLimitLocal(ctx, auth.ID)
	}
}

// runAuthHealthProbeWithLimitLocal 在信号量限制下运行健康探测，控制并发数。
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
	sem, _ := m.healthSemaphore.Load().(chan struct{})
	if sem == nil {
		m.runAuthHealthProbeLocal(ctx, auth)
		return
	}
	select {
	case sem <- struct{}{}:
		defer func(ch chan struct{}) { <-ch }(sem)
	case <-ctx.Done():
		return
	}
	m.runAuthHealthProbeLocal(ctx, auth)
}

// beginAuthHealthProbeLocal 标记健康探测开始，防止重复探测，返回认证快照。
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

// endAuthHealthProbeLocal 标记健康探测结束，清除忙碌状态。
func (m *Manager) endAuthHealthProbeLocal(authID string) {
	if m == nil {
		return
	}
	m.healthProbeBusy.Delete(strings.TrimSpace(authID))
}

// runAuthHealthProbeLocal 执行单个认证的健康探测，包括配额受限时的刷新。
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
	if DBStatusForAuth(auth) == DBStatusQuotaLimited {
		refreshCtx, refreshCancel := context.WithTimeout(context.Background(), 10*time.Second)
		refreshed, ok := m.refreshAuthForHealthProbe(refreshCtx, auth.ID)
		refreshCancel()
		if ok && refreshed != nil {
			auth = refreshed
		}
	}

	statusCode, body, errProbe := m.executeAuthHealthProbeLocal(ctx, auth)
	if errProbe != nil {
		log.WithError(errProbe).Debugf("auth health probe failed for %s (%s)", auth.Provider, auth.ID)
		decision := authHealthProbeDecisionLocal{
			DBStatus:   DBStatusDisabled,
			HTTPStatus: 0,
			Reason:     strings.TrimSpace(errProbe.Error()),
		}
		if shouldRetryAuthHealthProbeAfterErrorLocal(errProbe) {
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

// classifyAuthHealthProbeLocal 根据HTTP状态码和响应体分类健康探测结果，返回决策。
func (m *Manager) classifyAuthHealthProbeLocal(httpStatus int, body string) authHealthProbeDecisionLocal {
	httpStatus = normalizeAuthHealthProbeStatusCodeLocal(httpStatus, body)
	failure := extractCliproxyFailureReasonLocal(body, m.oauthHealthProbeMinRemainingWeeklyPercent())
	if httpStatus >= http.StatusBadRequest {
		reason := "HTTP " + strconv.Itoa(httpStatus)
		if failure != nil && strings.TrimSpace(failure.Reason) != "" {
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
			// 服务不可用且包含上下文超时信号，视为配额限制
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
		status := DBStatusDisabled
		httpStatusForReason := httpStatus
		if failure.QuotaLimited {
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

// normalizeAuthHealthProbeStatusCodeLocal 从响应体中提取真实的HTTP状态码。
func normalizeAuthHealthProbeStatusCodeLocal(httpStatus int, body string) int {
	decoded := decodePossibleJSONPayloadLocal(body)
	if data, ok := decoded.(map[string]any); ok {
		if statusCode, okStatus := intValueFromAnyLocal(data["status_code"]); okStatus && statusCode > 0 {
			return statusCode
		}
	}
	if httpStatus > 0 {
		return httpStatus
	}
	return http.StatusOK
}

// normalizeQuotaHealthProbeStatusCodeLocal 将配额限制的状态码标准化，零值替换为429。
func normalizeQuotaHealthProbeStatusCodeLocal(status int) int {
	if status == 0 || status == http.StatusOK {
		return http.StatusTooManyRequests
	}
	return status
}

// shouldRetryAuthHealthProbeAfterErrorLocal 判断错误是否为可重试的临时错误（如上下文超时）。
func shouldRetryAuthHealthProbeAfterErrorLocal(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(err.Error())), "context deadline exceeded")
}

// shouldRetryAuthHealthProbeResponseLocal 判断503响应是否包含上下文超时信号，决定是否可重试。
func shouldRetryAuthHealthProbeResponseLocal(httpStatus int, body string) bool {
	if httpStatus != http.StatusServiceUnavailable {
		return false
	}
	return containsDeadlineExceededSignalLocal(body)
}

// containsDeadlineExceededSignalLocal 递归检查载荷中是否包含上下文超时信号。
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

// detachedPersistContextLocal 创建独立的持久化上下文，与原始请求上下文分离。
func detachedPersistContextLocal(ctx context.Context) (context.Context, context.CancelFunc) {
	persistCtx, cancel := context.WithTimeout(context.Background(), healthProbePersistTimeout)
	if shouldSkipPersist(ctx) {
		persistCtx = WithSkipPersist(persistCtx)
	}
	return persistCtx, cancel
}

// applyAuthHealthProbeDecisionLocal 根据健康探测决策更新认证状态并通知相关组件。
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
		auth.DBStatus = nextDBStatus
		auth.UpdatedAt = now
		switch nextDBStatus {
		case DBStatusActive:
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
			auth.Disabled = false
			auth.Status = StatusError
			auth.Unavailable = true
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
			auth.NextRetryAfter = time.Time{}
			shouldUnregisterClient = true
		case DBStatusDisabled:
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
			shouldUnregisterClient = true
		}
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

// executeAuthHealthProbeLocal 执行实际的HTTP健康探测请求，返回状态码和响应体。
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

// supportsAuthHealthProbeLocal 判断认证是否支持健康探测（已禁用或API密钥类型不支持）。
func supportsAuthHealthProbeLocal(auth *Auth) bool {
	if auth == nil {
		return false
	}
	switch DBStatusForAuth(auth) {
	case DBStatusDisabled:
		return false
	}
	if isAPIKeyAuth(auth) {
		return false
	}
	_, ok := authHealthProbeSpecForAuthLocal(auth)
	return ok
}

// authHealthProbeSpecForAuthLocal 根据认证的Provider类型返回对应的健康探测规格。
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

// codexAuthHealthProbeSpecLocal 为Codex类型认证构造健康探测规格（wham/usage端点）。
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
	if auth.Metadata != nil {
		if accountID, ok := auth.Metadata["account_id"].(string); ok {
			if trimmed := strings.TrimSpace(accountID); trimmed != "" {
				headers.Set("Chatgpt-Account-Id", trimmed)
			}
		}
	}
	if len(headers.Values("Chatgpt-Account-Id")) == 0 && auth.Attributes != nil {
		if accountID := strings.TrimSpace(auth.Attributes["account_id"]); accountID != "" {
			headers.Set("Chatgpt-Account-Id", accountID)
		}
	}
	return &authHealthProbeSpecLocal{
		Method:  http.MethodGet,
		URL:     baseURL + "/wham/usage",
		Headers: headers,
	}, true
}

// decodePossibleJSONPayloadLocal 尝试将载荷解码为JSON，无法解码则返回原始字符串。
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
			return decoded
		}
		return trimmed
	case []byte:
		return decodePossibleJSONPayloadLocal(string(typed))
	default:
		return payload
	}
}

// extractCliproxyFailureReasonLocal 从响应载荷中递归提取失败原因及配额限制状态。
func extractCliproxyFailureReasonLocal(payload any, minRemainingWeeklyPercent int) *authHealthProbeFailureLocal {
	data := decodePossibleJSONPayloadLocal(payload)
	switch typed := data.(type) {
	case string:
		keyword, ok := knownCliproxyKeywordLocal(typed)
		if !ok {
			return nil
		}
		return &authHealthProbeFailureLocal{
			Reason:       formatKnownCliproxyErrorLocal(keyword),
			QuotaLimited: isCliproxyQuotaKeywordLocal(keyword),
		}
	case map[string]any:
		errorValue, _ := typed["error"].(map[string]any)
		if errorValue != nil {
			if errType, okType := stringValueFromAnyLocal(errorValue["type"]); okType && strings.TrimSpace(errType) != "" {
				return &authHealthProbeFailureLocal{
					Reason:       formatKnownCliproxyErrorLocal(strings.TrimSpace(errType)),
					QuotaLimited: isCliproxyQuotaKeywordLocal(strings.TrimSpace(errType)),
				}
			}
			if errMessage, okMessage := stringValueFromAnyLocal(errorValue["message"]); okMessage && strings.TrimSpace(errMessage) != "" {
				keyword, foundKeyword := knownCliproxyKeywordLocal(errMessage)
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
				if failure := extractRateLimitReasonLocal(rateInfo, key, 0); failure != nil {
					return failure
				}
			}
		case map[string]any:
			for key, rateInfo := range additional {
				if failure := extractRateLimitReasonLocal(rateInfo, "additional_rate_limits."+key, 0); failure != nil {
					return failure
				}
			}
		}

		for _, key := range []string{"data", "body", "response", "text", "content", "status_message"} {
			if failure := extractCliproxyFailureReasonLocal(typed[key], minRemainingWeeklyPercent); failure != nil {
				return failure
			}
		}

		if encoded, errMarshal := json.Marshal(typed); errMarshal == nil {
			if keyword, okKeyword := knownCliproxyKeywordLocal(string(encoded)); okKeyword {
				return &authHealthProbeFailureLocal{
					Reason:       formatKnownCliproxyErrorLocal(keyword),
					QuotaLimited: isCliproxyQuotaKeywordLocal(keyword),
				}
			}
		}
	}
	return nil
}

// extractRateLimitReasonLocal 从速率限制信息中提取失败原因。
func extractRateLimitReasonLocal(rateInfo any, key string, minRemainingWeeklyPercent int) *authHealthProbeFailureLocal {
	data, ok := decodePossibleJSONPayloadLocal(rateInfo).(map[string]any)
	if !ok {
		return nil
	}
	allowed, hasAllowed := boolValueFromAnyLocal(data["allowed"])
	limitReached, hasLimitReached := boolValueFromAnyLocal(data["limit_reached"])
	if (hasAllowed && !allowed) || (hasLimitReached && limitReached) {
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
			return &authHealthProbeFailureLocal{
				Reason:       "weekly quota remaining " + formatPercentLocal(remainingPercent) + "% is below " + strconv.Itoa(minRemainingWeeklyPercent) + "%",
				QuotaLimited: true,
			}
		}
	}
	return nil
}

// extractRemainingPercentLocal 从速率窗口数据中提取剩余百分比。
func extractRemainingPercentLocal(payload any) (float64, bool) {
	data, ok := decodePossibleJSONPayloadLocal(payload).(map[string]any)
	if !ok {
		return 0, false
	}
	if remainingPercent, okRemaining := floatValueFromAnyLocal(data["remaining_percent"]); okRemaining {
		return clampPercentLocal(remainingPercent), true
	}
	if usedPercent, okUsed := floatValueFromAnyLocal(data["used_percent"]); okUsed {
		return clampPercentLocal(100 - usedPercent), true
	}
	return 0, false
}

// clampPercentLocal 将百分比值限制在0到100之间。
func clampPercentLocal(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

// formatPercentLocal 将浮点数格式化为百分比字符串，去除尾部多余零。
func formatPercentLocal(value float64) string {
	rounded := strconv.FormatFloat(value, 'f', 2, 64)
	rounded = strings.TrimRight(strings.TrimRight(rounded, "0"), ".")
	if rounded == "" {
		return "0"
	}
	return rounded
}

// knownCliproxyKeywordLocal 检查字符串中是否包含已知的CLIProxy错误关键字。
func knownCliproxyKeywordLocal(value string) (string, bool) {
	value = strings.ToLower(value)
	for _, keyword := range []string{"usage_limit_reached", "account_deactivated", "insufficient_quota", "invalid_api_key", "unsupported_region"} {
		if strings.Contains(value, keyword) {
			return keyword, true
		}
	}
	return "", false
}

// isCliproxyQuotaKeywordLocal 判断关键字是否为配额相关的错误。
func isCliproxyQuotaKeywordLocal(keyword string) bool {
	switch strings.TrimSpace(keyword) {
	case "usage_limit_reached", "insufficient_quota":
		return true
	default:
		return false
	}
}

// formatKnownCliproxyErrorLocal 将已知错误关键字格式化为可读的错误消息。
func formatKnownCliproxyErrorLocal(keyword string) string {
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

// stringValueFromAnyLocal 尝试将任意值转换为字符串。
func stringValueFromAnyLocal(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case json.Number:
		return typed.String(), true
	}
	return "", false
}

// boolValueFromAnyLocal 尝试将任意值转换为布尔值。
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

// floatValueFromAnyLocal 尝试将任意值转换为float64。
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

// intValueFromAnyLocal 尝试将任意值转换为int。
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

// healthProbeFailureReasonLocal 构造健康探测失败原因的JSON字符串。
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

// unauthorizedHealthProbeReasonLocal 构造未授权(401)健康探测失败原因。
func unauthorizedHealthProbeReasonLocal(body string) string {
	return healthProbeFailureReasonLocal(http.StatusUnauthorized, body)
}
