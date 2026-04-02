package auth

import (
	"strings"
	"time"
)

// Status represents the lifecycle state of an Auth entry.
type Status string

const (
	// StatusUnknown means the auth state could not be determined.
	StatusUnknown Status = "unknown"
	// StatusActive indicates the auth is valid and ready for execution.
	StatusActive Status = "active"
	// StatusPending indicates the auth is waiting for an external action, such as MFA.
	StatusPending Status = "pending"
	// StatusRefreshing indicates the auth is undergoing a refresh flow.
	StatusRefreshing Status = "refreshing"
	// StatusError indicates the auth is temporarily unavailable due to errors.
	StatusError Status = "error"
	// StatusDisabled marks the auth as intentionally disabled.
	StatusDisabled Status = "disabled"
)

const (
	// DBStatusActive 表示账号正常，可参与请求轮询和定时复检。
	DBStatusActive = 1
	// DBStatusDisabled 表示账号已失活，后续不再自动复检。
	DBStatusDisabled = 2
	// DBStatusQuotaLimited 表示账号还活着，但额度不足，需要等待后续定时复检恢复。
	DBStatusQuotaLimited = 3
)

// NormalizeDBStatus 把数据库里的状态值收敛到当前支持的 1/2/3，避免旧值或脏值影响运行时判断。
func NormalizeDBStatus(status int) int {
	switch status {
	case DBStatusDisabled, DBStatusQuotaLimited:
		// 当前只允许 2 和 3 原样保留，其他值统一回收到 1。
		return status
	default:
		return DBStatusActive
	}
}

// DBStatusForAuth 返回 auth 当前应落库的状态值。
// 这里优先使用显式写入的 DBStatus，其次再根据 Disabled/Status 做兜底判断。
func DBStatusForAuth(auth *Auth) int {
	if auth == nil {
		return DBStatusActive
	}
	if auth.DBStatus != 0 {
		// 运行时已经明确写过 DBStatus 时，优先使用它，避免再次推导把状态改回去。
		return NormalizeDBStatus(auth.DBStatus)
	}
	if auth.Disabled || auth.Status == StatusDisabled {
		// 没有显式 DBStatus 时，沿用旧逻辑把明确停用的账号视为 2。
		return DBStatusDisabled
	}
	return DBStatusActive
}

// FormatAutoDisabledStatusMessage 用于生成自动停用后的状态说明。
// 当前规则很简单：优先原样返回原始错误串，不再拼接额外文案。
func FormatAutoDisabledStatusMessage(reason string, _ time.Time) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		// 只有完全没有拿到原始错误串时，才退回到一个兜底文案。
		reason = "permanently disabled by upstream"
	}
	return reason
}
