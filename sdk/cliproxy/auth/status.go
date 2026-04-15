package auth

import (
	"strings"
	"time"
)

// Status 表示认证条目的生命周期状态。
type Status string

const (
	// StatusUnknown 表示无法确定认证状态。
	StatusUnknown Status = "unknown"
	// StatusActive 表示认证有效且可执行。
	StatusActive Status = "active"
	// StatusPending 表示认证正在等待外部操作，例如 MFA。
	StatusPending Status = "pending"
	// StatusRefreshing 表示认证正在进行刷新流程。
	StatusRefreshing Status = "refreshing"
	// StatusError 表示认证因错误暂时不可用。
	StatusError Status = "error"
	// StatusDisabled 标记认证为手动禁用状态。
	StatusDisabled Status = "disabled"
)

const (
	// DBStatusActive 表示凭证处于活跃状态。
	DBStatusActive = 1
	// DBStatusDisabled 表示凭证已被永久禁用。
	DBStatusDisabled = 2
	// DBStatusQuotaLimited 表示凭证存活但暂时受到配额限制。
	DBStatusQuotaLimited = 3
)

// NormalizeDBStatus 将任意数据库值归约为支持的状态。
func NormalizeDBStatus(status int) int {
	switch status {
	case DBStatusDisabled, DBStatusQuotaLimited:
		return status
	default:
		return DBStatusActive
	}
}

// DBStatusForAuth 返回认证的有效持久化数据库状态。
func DBStatusForAuth(auth *Auth) int {
	if auth == nil {
		return DBStatusActive
	}
	if auth.DBStatus != 0 {
		return NormalizeDBStatus(auth.DBStatus)
	}
	if auth.Disabled || auth.Status == StatusDisabled {
		return DBStatusDisabled
	}
	return DBStatusActive
}

// IsAuthDisabled 当认证应被视为已禁用时返回 true。
func IsAuthDisabled(auth *Auth) bool {
	if auth == nil {
		return false
	}
	if NormalizeDBStatus(DBStatusForAuth(auth)) == DBStatusDisabled {
		return true
	}
	return auth.Disabled || auth.Status == StatusDisabled
}

// IsAuthQuotaLimited 当认证处于配额限制状态时返回 true。
func IsAuthQuotaLimited(auth *Auth) bool {
	if auth == nil {
		return false
	}
	return NormalizeDBStatus(DBStatusForAuth(auth)) == DBStatusQuotaLimited
}

// IsAuthActiveForRouting 当认证可以参与路由时返回 true。
func IsAuthActiveForRouting(auth *Auth) bool {
	if auth == nil || strings.TrimSpace(auth.ID) == "" {
		return false
	}
	if NormalizeDBStatus(DBStatusForAuth(auth)) != DBStatusActive {
		return false
	}
	return !auth.Disabled && auth.Status != StatusDisabled
}

// ApplyManualDisabled 为管理操作应用一致的禁用状态。
func ApplyManualDisabled(auth *Auth, reason string, now time.Time) {
	if auth == nil {
		return
	}
	auth.DBStatus = DBStatusDisabled
	auth.Disabled = true
	auth.Unavailable = false
	auth.Status = StatusDisabled
	auth.StatusMessage = strings.TrimSpace(reason)
	if auth.StatusMessage == "" {
		auth.StatusMessage = "disabled via management API"
	}
	auth.NextRetryAfter = time.Time{}
	auth.Quota = QuotaState{}
	auth.UpdatedAt = now
}

// ApplyManualEnabled 为管理操作应用一致的活跃状态。
func ApplyManualEnabled(auth *Auth, now time.Time) {
	if auth == nil {
		return
	}
	auth.DBStatus = DBStatusActive
	auth.Disabled = false
	auth.Unavailable = false
	auth.Status = StatusActive
	auth.StatusMessage = ""
	auth.LastError = nil
	auth.NextRetryAfter = time.Time{}
	auth.Quota = QuotaState{}
	auth.UpdatedAt = now
}

// FormatAutoDisabledStatusMessage 当认证被自动禁用时返回一条稳定的消息。
func FormatAutoDisabledStatusMessage(reason string, _ time.Time) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "permanently disabled by upstream"
	}
	return reason
}
