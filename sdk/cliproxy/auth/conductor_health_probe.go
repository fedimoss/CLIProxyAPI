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

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	log "github.com/sirupsen/logrus"
)

// MarkResultLocal records execution results for auth state updates.
// Health probes are triggered only by the periodic scheduler.
func (m *Manager) MarkResultLocal(ctx context.Context, result Result) {
	m.MarkResult(ctx, result)
}

// authHealthProbeSpecLocal 瀹氫箟鍋ュ悍鎺㈡祴鐨勮姹傝鏍硷紝鍖呮嫭鏂规硶銆乁RL鍜岃姹傚ご銆?
type authHealthProbeSpecLocal struct {
	Method  string
	URL     string
	Headers http.Header
}

// authHealthProbeFailureLocal 琛ㄧず鍋ュ悍鎺㈡祴澶辫触鐨勫師鍥犲強鏄惁涓洪厤棰濋檺鍒躲€?
type authHealthProbeFailureLocal struct {
	Reason       string
	QuotaLimited bool
}

// authHealthProbeDecisionLocal 琛ㄧず鍋ュ悍鎺㈡祴鐨勫喅绛栫粨鏋滐紝鍖呭惈鏁版嵁搴撶姸鎬併€丠TTP鐘舵€佺爜鍜屽師鍥犮€?
type authHealthProbeDecisionLocal struct {
	DBStatus   int
	HTTPStatus int
	Reason     string
}

// checkAuthHealthProbesLocal 妫€鏌ユ墍鏈夋敮鎸佸仴搴锋帰娴嬬殑璁よ瘉锛屾壒閲忓惎鍔ㄦ帰娴嬨€?
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

// runAuthHealthProbeWithLimitLocal 鍦ㄤ俊鍙烽噺闄愬埗涓嬭繍琛屽仴搴锋帰娴嬶紝鎺у埗骞跺彂鏁般€?
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

// beginAuthHealthProbeLocal 鏍囪鍋ュ悍鎺㈡祴寮€濮嬶紝闃叉閲嶅鎺㈡祴锛岃繑鍥炶璇佸揩鐓с€?
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

// endAuthHealthProbeLocal 鏍囪鍋ュ悍鎺㈡祴缁撴潫锛屾竻闄ゅ繖纰岀姸鎬併€?
func (m *Manager) endAuthHealthProbeLocal(authID string) {
	if m == nil {
		return
	}
	m.healthProbeBusy.Delete(strings.TrimSpace(authID))
}

// runAuthHealthProbeLocal 鎵ц鍗曚釜璁よ瘉鐨勫仴搴锋帰娴嬶紝鍖呮嫭閰嶉鍙楅檺鏃剁殑鍒锋柊銆?
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

// classifyAuthHealthProbeLocal 鏍规嵁HTTP鐘舵€佺爜鍜屽搷搴斾綋鍒嗙被鍋ュ悍鎺㈡祴缁撴灉锛岃繑鍥炲喅绛栥€?
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
			// 鏈嶅姟涓嶅彲鐢ㄤ笖鍖呭惈涓婁笅鏂囪秴鏃朵俊鍙凤紝瑙嗕负閰嶉闄愬埗
			return authHealthProbeDecisionLocal{
				DBStatus:   DBStatusQuotaLimited,
				HTTPStatus: httpStatus,
				Reason:     healthProbeFailureReasonLocal(httpStatus, body),
			}
		}
		// 鍘熷洜: OpenAI鏈嶅姟鏈嶅姟鏁呴殰锛岃繑鍥?{"status":403,"detail":"Forbidden","message":"HTTP 403"}"锛岃璇垽涓鸿处鍙峰皝绂侊紝淇敼涓虹姸鎬?
		// 瑙ｅ喅: 閬囧埌"{"status":403,"detail":"Forbidden","message":"HTTP 403"}"锛岃涓洪搴﹀彈闄愶紝淇敼涓虹姸鎬?锛屼互渚垮悗缁妫€鑷姩鎭㈠
		if httpStatus == http.StatusForbidden && isGenericForbiddenResponseLocal(body) {
			return authHealthProbeDecisionLocal{
				DBStatus:   DBStatusQuotaLimited,
				HTTPStatus: httpStatus,
				Reason:     reason,
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

// normalizeAuthHealthProbeStatusCodeLocal 浠庡搷搴斾綋涓彁鍙栫湡瀹炵殑HTTP鐘舵€佺爜銆?
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

// normalizeQuotaHealthProbeStatusCodeLocal 灏嗛厤棰濋檺鍒剁殑鐘舵€佺爜鏍囧噯鍖栵紝闆跺€兼浛鎹负429銆?
func normalizeQuotaHealthProbeStatusCodeLocal(status int) int {
	if status == 0 || status == http.StatusOK {
		return http.StatusTooManyRequests
	}
	return status
}

// isGenericForbiddenResponseLocal 鍒ゆ柇鍝嶅簲浣撴槸鍚︿负閫氱敤鐨勭┖ 403 鍝嶅簲锛堟棤鍏蜂綋閿欒淇℃伅锛夈€?
func isGenericForbiddenResponseLocal(body string) bool {
	decoded := decodePossibleJSONPayloadLocal(body)
	data, ok := decoded.(map[string]any)
	if !ok {
		return false
	}
	statusCode, hasStatus := intValueFromAnyLocal(data["status"])
	detail, hasDetail := stringValueFromAnyLocal(data["detail"])
	message, hasMessage := stringValueFromAnyLocal(data["message"])
	return hasStatus && statusCode == http.StatusForbidden &&
		hasDetail && strings.TrimSpace(detail) == "Forbidden" &&
		hasMessage && strings.TrimSpace(message) == "HTTP 403"
}

// shouldRetryAuthHealthProbeAfterErrorLocal 鍒ゆ柇閿欒鏄惁涓哄彲閲嶈瘯鐨勪复鏃堕敊璇紙濡備笂涓嬫枃瓒呮椂锛夈€?
func shouldRetryAuthHealthProbeAfterErrorLocal(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(err.Error())), "context deadline exceeded")
}

// shouldRetryAuthHealthProbeResponseLocal 鍒ゆ柇503鍝嶅簲鏄惁鍖呭惈涓婁笅鏂囪秴鏃朵俊鍙凤紝鍐冲畾鏄惁鍙噸璇曘€?
func shouldRetryAuthHealthProbeResponseLocal(httpStatus int, body string) bool {
	if httpStatus != http.StatusServiceUnavailable {
		return false
	}
	return containsDeadlineExceededSignalLocal(body)
}

// containsDeadlineExceededSignalLocal 閫掑綊妫€鏌ヨ浇鑽蜂腑鏄惁鍖呭惈涓婁笅鏂囪秴鏃朵俊鍙枫€?
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

// detachedPersistContextLocal 鍒涘缓鐙珛鐨勬寔涔呭寲涓婁笅鏂囷紝涓庡師濮嬭姹備笂涓嬫枃鍒嗙銆?
func detachedPersistContextLocal(ctx context.Context) (context.Context, context.CancelFunc) {
	persistCtx, cancel := context.WithTimeout(context.Background(), healthProbePersistTimeout)
	if shouldSkipPersist(ctx) {
		persistCtx = WithSkipPersist(persistCtx)
	}
	return persistCtx, cancel
}

// applyAuthHealthProbeDecisionLocal 鏍规嵁鍋ュ悍鎺㈡祴鍐崇瓥鏇存柊璁よ瘉鐘舵€佸苟閫氱煡鐩稿叧缁勪欢銆?
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

// executeAuthHealthProbeLocal 鎵ц瀹為檯鐨凥TTP鍋ュ悍鎺㈡祴璇锋眰锛岃繑鍥炵姸鎬佺爜鍜屽搷搴斾綋銆?
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

// supportsAuthHealthProbeLocal 鍒ゆ柇璁よ瘉鏄惁鏀寔鍋ュ悍鎺㈡祴锛堝凡绂佺敤鎴朅PI瀵嗛挜绫诲瀷涓嶆敮鎸侊級銆?
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

// authHealthProbeSpecForAuthLocal 鏍规嵁璁よ瘉鐨凱rovider绫诲瀷杩斿洖瀵瑰簲鐨勫仴搴锋帰娴嬭鏍笺€?
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

// codexAuthHealthProbeSpecLocal 涓篊odex绫诲瀷璁よ瘉鏋勯€犲仴搴锋帰娴嬭鏍硷紙wham/usage绔偣锛夈€?
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

// decodePossibleJSONPayloadLocal 灏濊瘯灏嗚浇鑽疯В鐮佷负JSON锛屾棤娉曡В鐮佸垯杩斿洖鍘熷瀛楃涓层€?
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

// extractCliproxyFailureReasonLocal 浠庡搷搴旇浇鑽蜂腑閫掑綊鎻愬彇澶辫触鍘熷洜鍙婇厤棰濋檺鍒剁姸鎬併€?
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

// extractRateLimitReasonLocal 浠庨€熺巼闄愬埗淇℃伅涓彁鍙栧け璐ュ師鍥犮€?
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

// extractRemainingPercentLocal 浠庨€熺巼绐楀彛鏁版嵁涓彁鍙栧墿浣欑櫨鍒嗘瘮銆?
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

// clampPercentLocal 灏嗙櫨鍒嗘瘮鍊奸檺鍒跺湪0鍒?00涔嬮棿銆?
func clampPercentLocal(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

// formatPercentLocal 灏嗘诞鐐规暟鏍煎紡鍖栦负鐧惧垎姣斿瓧绗︿覆锛屽幓闄ゅ熬閮ㄥ浣欓浂銆?
func formatPercentLocal(value float64) string {
	rounded := strconv.FormatFloat(value, 'f', 2, 64)
	rounded = strings.TrimRight(strings.TrimRight(rounded, "0"), ".")
	if rounded == "" {
		return "0"
	}
	return rounded
}

// knownCliproxyKeywordLocal 妫€鏌ュ瓧绗︿覆涓槸鍚﹀寘鍚凡鐭ョ殑CLIProxy閿欒鍏抽敭瀛椼€?
func knownCliproxyKeywordLocal(value string) (string, bool) {
	value = strings.ToLower(value)
	for _, keyword := range []string{"usage_limit_reached", "account_deactivated", "insufficient_quota", "invalid_api_key", "unsupported_region"} {
		if strings.Contains(value, keyword) {
			return keyword, true
		}
	}
	return "", false
}

// isCliproxyQuotaKeywordLocal 鍒ゆ柇鍏抽敭瀛楁槸鍚︿负閰嶉鐩稿叧鐨勯敊璇€?
func isCliproxyQuotaKeywordLocal(keyword string) bool {
	switch strings.TrimSpace(keyword) {
	case "usage_limit_reached", "insufficient_quota":
		return true
	default:
		return false
	}
}

// formatKnownCliproxyErrorLocal 灏嗗凡鐭ラ敊璇叧閿瓧鏍煎紡鍖栦负鍙鐨勯敊璇秷鎭€?
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

// CheckQuotaExhaustion 妫€鏌?API 鍝嶅簲浣撴槸鍚﹁〃绀洪厤棰濊€楀敖锛堢敤浜?APICall 璺緞锛夈€?
//
// 鍒ゆ柇閫昏緫鍒嗕袱姝ワ細
//  1. 澶嶇敤瀹氭椂鍋ュ悍鎺㈡祴閫昏緫锛坋xtractCliproxyFailureReasonLocal锛夛紝閫氳繃 config.yaml 涓?
//     min-remaining-weekly-percent 闃堝€煎垽鏂搴︽槸鍚﹀厖瓒炽€傛敮鎸佹爣鍑?error 瀵硅薄銆乺ate_limit 绛夋牸寮忋€?
//  2. 瑙ｆ瀽 Codex usage 鏁扮粍鏍煎紡锛岄亶鍘嗘瘡涓厓绱犲強宓屽 usage 鏁扮粍锛?
//     妫€鏌?usage_limit_reached 涓?true锛堝竷灏斿€硷級涓?resets_in_seconds > 1800锛?0鍒嗛挓锛夈€?
//
// 涓?MarkResult 璺緞鐨勫尯鍒細
//   - MarkResult 璺緞妫€鏌ョ殑鏄敊璇搷搴斾腑 type="usage_limit_reached"锛堝瓧绗︿覆锛? resets_in_seconds > 1800
//   - 鏈柟娉曪紙APICall 璺緞锛夐澶栨敮鎸?Codex usage 鏁扮粍涓?usage_limit_reached: true锛堝竷灏斿€硷級鐨勬鏌?
//
// 杩斿洖鏄惁閰嶉鍙楅檺鍙婂師鍥犳弿杩般€?
func (m *Manager) CheckQuotaExhaustion(body string) (quotaLimited bool, reason string) {
	if m == nil || strings.TrimSpace(body) == "" {
		return false, ""
	}

	minRemaining := m.oauthHealthProbeMinRemainingWeeklyPercent()

	// 1. 鍏堢敤鏍囧噯鍋ュ悍鎺㈡祴閫昏緫妫€鏌ワ紙澶勭悊 error 瀵硅薄銆乺ate_limit 绛夋牸寮忥級
	if failure := extractCliproxyFailureReasonLocal(body, minRemaining); failure != nil {
		return failure.QuotaLimited, failure.Reason
	}

	// 2. 灏濊瘯瑙ｆ瀽涓?JSON 鏁扮粍锛圕odex usage 鏍煎紡锛?
	// [{"type":"codex","usage_limit_reached":false,...,"usage":[{"type":"code_search","usage_limit_reached":true,"resets_in_seconds":86400,...}]}]
	decoded := decodePossibleJSONPayloadLocal(body)
	arr, ok := decoded.([]any)
	if !ok {
		return false, ""
	}

	var checkItems []map[string]any
	for _, item := range arr {
		if obj, ok := item.(map[string]any); ok {
			checkItems = append(checkItems, obj)
			if usageArr, ok := obj["usage"].([]any); ok {
				for _, usageItem := range usageArr {
					if usageObj, ok := usageItem.(map[string]any); ok {
						checkItems = append(checkItems, usageObj)
					}
				}
			}
		}
	}

	for _, item := range checkItems {
		if limitReached, _ := boolValueFromAnyLocal(item["usage_limit_reached"]); limitReached {
			resetsInSeconds, _ := intValueFromAnyLocal(item["resets_in_seconds"])
			if resetsInSeconds > 1800 {
				itemType, _ := stringValueFromAnyLocal(item["type"])
				reason := "usage limit reached"
				if strings.TrimSpace(itemType) != "" {
					reason = "usage limit reached (" + strings.TrimSpace(itemType) + ")"
				}
				return true, reason
			}
		}
	}

	return false, ""
}

// stringValueFromAnyLocal 灏濊瘯灏嗕换鎰忓€艰浆鎹负瀛楃涓层€?
func stringValueFromAnyLocal(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case json.Number:
		return typed.String(), true
	}
	return "", false
}

// boolValueFromAnyLocal 灏濊瘯灏嗕换鎰忓€艰浆鎹负甯冨皵鍊笺€?
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

// floatValueFromAnyLocal 灏濊瘯灏嗕换鎰忓€艰浆鎹负float64銆?
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

// intValueFromAnyLocal 灏濊瘯灏嗕换鎰忓€艰浆鎹负int銆?
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

// healthProbeFailureReasonLocal 鏋勯€犲仴搴锋帰娴嬪け璐ュ師鍥犵殑JSON瀛楃涓层€?
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

// unauthorizedHealthProbeReasonLocal 鏋勯€犳湭鎺堟潈(401)鍋ュ悍鎺㈡祴澶辫触鍘熷洜銆?
func unauthorizedHealthProbeReasonLocal(body string) string {
	return healthProbeFailureReasonLocal(http.StatusUnauthorized, body)
}
