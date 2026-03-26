package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitee.com/chunanyong/zorm"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/entity"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// DBTokenStore 基于 zorm 和 cli_oauth 表实现 auth 存储。
type DBTokenStore struct{}

// NewDBTokenStore 创建数据库 Token 存储实例。
func NewDBTokenStore() *DBTokenStore {
	return &DBTokenStore{}
}

// SetBaseDir 数据库存储不依赖目录，保留空实现以兼容调用方接口。
func (s *DBTokenStore) SetBaseDir(_ string) {}

// SkipFileAuth 表示该存储独立于文件系统，不需要文件监听器参与。
func (s *DBTokenStore) SkipFileAuth() bool { return true }

// List 从 cli_oauth 表查询所有 auth 记录。
func (s *DBTokenStore) List(ctx context.Context) ([]*cliproxyauth.Auth, error) {
	finder := zorm.NewSelectFinder((&entity.CLIOauth{}).GetTableName())
	finder.Append(" order by created_at desc")

	var authList []entity.CLIOauth
	if err := zorm.Query(ctx, finder, &authList, nil); err != nil {
		return nil, fmt.Errorf("dbstore: 查询 auth 失败: %w", err)
	}

	auths := make([]*cliproxyauth.Auth, 0, len(authList))
	for _, item := range authList {
		auth, err := s.rowToAuth(item)
		if err != nil {
			continue
		}
		auths = append(auths, auth)
	}
	return auths, nil
}

// Save 将 auth 记录保存到 cli_oauth 表。
func (s *DBTokenStore) Save(ctx context.Context, auth *cliproxyauth.Auth) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("dbstore: auth 为空")
	}

	var oauthJSON []byte
	var err error
	if auth.Metadata != nil {
		oauthJSON, err = json.Marshal(auth.Metadata)
		if err != nil {
			return "", fmt.Errorf("dbstore: 序列化 metadata 失败: %w", err)
		}
	} else {
		return "", fmt.Errorf("dbstore: %s 无可持久化数据", auth.ID)
	}

	now := time.Now()
	record := entity.CLIOauth{
		Oauth:     string(oauthJSON),
		ModelType: providerToModelType(auth.Provider),
		UpdatedAt: &now,
	}
	record.ID = auth.ID

	existing, err := s.findByID(ctx, auth.ID)
	if err != nil {
		return "", fmt.Errorf("dbstore: 查询已有记录失败: %w", err)
	}

	// cli_oauth.status 约定：1=正常，2=禁用。
	// 如果当前 auth 已明确停用，就写 2；否则保留数据库原状态，避免刷新时误改状态。
	status := 1
	if existing != nil && existing.Status != 0 {
		status = existing.Status
	}
	if auth.Disabled || auth.Status == cliproxyauth.StatusDisabled {
		status = 2
	}
	record.Status = status
	if status == 2 {
		// 只要当前记录已经是禁用状态，就把原始错误串写入 error_reason。
		// 这样后面无论是重启恢复，还是前端查看，都能看到同一份原始错误内容。
		record.ErrorReason = disabledErrorReason(auth)
		if record.ErrorReason == "" && existing != nil {
			// 如果这次内存里没带错误串，就沿用数据库里已有的那份。
			// 这样可以避免一次普通更新把原来的停用原因冲掉。
			record.ErrorReason = strings.TrimSpace(existing.ErrorReason)
		}
	}

	_, err = zorm.Transaction(ctx, func(txCtx context.Context) (interface{}, error) {
		if existing != nil {
			record.CreatedAt = existing.CreatedAt
			return zorm.Update(txCtx, &record)
		}
		record.CreatedAt = &now
		return zorm.Insert(txCtx, &record)
	})
	if err != nil {
		return "", fmt.Errorf("dbstore: 保存 auth 失败: %w", err)
	}

	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	if strings.TrimSpace(auth.FileName) == "" {
		auth.FileName = auth.ID
	}

	return auth.ID, nil
}

// Delete 按 ID 删除 cli_oauth 记录。
func (s *DBTokenStore) Delete(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("dbstore: id 为空")
	}

	finder := zorm.NewDeleteFinder((&entity.CLIOauth{}).GetTableName())
	finder.Append(" where id=?", id)

	_, err := zorm.Transaction(ctx, func(txCtx context.Context) (interface{}, error) {
		return zorm.UpdateFinder(txCtx, finder)
	})
	if err != nil {
		return fmt.Errorf("dbstore: 删除 auth 失败: %w", err)
	}
	return nil
}

// findByID 按 ID 查询单条 cli_oauth 记录。
func (s *DBTokenStore) findByID(ctx context.Context, id string) (*entity.CLIOauth, error) {
	finder := zorm.NewSelectFinder((&entity.CLIOauth{}).GetTableName())
	finder.Append(" where id=?", id)

	var list []entity.CLIOauth
	if err := zorm.Query(ctx, finder, &list, nil); err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	return &list[0], nil
}

// rowToAuth 将 CLIOauth 数据库记录转换为运行时 auth 对象。
func (s *DBTokenStore) rowToAuth(item entity.CLIOauth) (*cliproxyauth.Auth, error) {
	metadata := make(map[string]any)
	if err := json.Unmarshal([]byte(item.Oauth), &metadata); err != nil {
		return nil, fmt.Errorf("dbstore: 解析 %s 的 oauth JSON 失败: %w", item.ID, err)
	}

	// 优先使用 oauth 原始数据里的 type，缺失时再根据 model_type 兜底。
	provider := strings.TrimSpace(valueAsString(metadata["type"]))
	if provider == "" {
		provider = modelTypeToProvider(item.ModelType)
	}

	// 数据库 status=2 代表明确停用；否则再回退看 metadata 里的 disabled 标记。
	disabled := false
	if item.Status == 2 {
		disabled = true
	} else if d, ok := metadata["disabled"].(bool); ok {
		disabled = d
	}

	status := cliproxyauth.StatusActive
	if disabled {
		status = cliproxyauth.StatusDisabled
	}

	// path 属性保持为 ID，避免管理接口构造返回数据时拿到空路径。
	attr := map[string]string{"path": item.ID}
	if email := strings.TrimSpace(valueAsString(metadata["email"])); email != "" {
		attr["email"] = email
	}

	auth := &cliproxyauth.Auth{
		ID:               item.ID,
		Provider:         provider,
		FileName:         item.ID,
		Label:            labelFor(metadata),
		Status:           status,
		Disabled:         disabled,
		Attributes:       attr,
		Metadata:         metadata,
		LastRefreshedAt:  time.Time{},
		NextRefreshAfter: time.Time{},
	}
	if disabled && strings.TrimSpace(item.ErrorReason) != "" {
		// 从数据库把禁用 auth 重新读回内存时，
		// 这里把 error_reason 再还原成运行时错误对象。
		// 这样后面的管理页、接口返回、状态判断拿到的都是同一份原始内容。
		auth.LastError = &cliproxyauth.Error{
			Code:       "account_deactivated",
			Message:    strings.TrimSpace(item.ErrorReason),
			HTTPStatus: http.StatusUnauthorized,
		}
	}

	if item.CreatedAt != nil {
		auth.CreatedAt = *item.CreatedAt
	}
	if item.UpdatedAt != nil {
		auth.UpdatedAt = *item.UpdatedAt
	}
	if disabled && strings.TrimSpace(item.ErrorReason) != "" {
		// 对外展示时，直接把原始错误串塞进状态说明。
		// 不额外拼接时间和前缀，确保前端看到的内容和数据库里的 error_reason 完全一致。
		rawReason := strings.TrimSpace(item.ErrorReason)
		auth.StatusMessage = rawReason
	}

	return auth, nil
}

// disabledErrorReason 从运行时状态里取出原始错误文本，用于写入 error_reason 字段。
func disabledErrorReason(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.LastError != nil {
		// 优先取运行时里最近一次失败留下的原始错误串。
		// 这里不做任何加工，直接保留上游原文。
		if reason := strings.TrimSpace(auth.LastError.Message); reason != "" {
			return reason
		}
	}
	return ""
}

// providerToModelType 将 provider 字符串映射为 model_type 整数。
func providerToModelType(provider string) int {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex":
		return 1
	case "claude", "anthropic":
		return 2
	case "qwen":
		return 3
	case "gemini", "antigravity":
		return 4
	case "kimi":
		return 5
	case "iflow":
		return 6
	default:
		return 0
	}
}

// modelTypeToProvider 将 model_type 整数反向映射为 provider 字符串。
func modelTypeToProvider(modelType int) string {
	switch modelType {
	case 1:
		return "codex"
	case 2:
		return "claude"
	case 3:
		return "qwen"
	case 4:
		return "gemini"
	case 5:
		return "kimi"
	case 6:
		return "iflow"
	default:
		return "unknown"
	}
}
