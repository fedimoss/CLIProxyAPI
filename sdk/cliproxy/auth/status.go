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
