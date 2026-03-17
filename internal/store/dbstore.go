package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gitee.com/chunanyong/zorm"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/entity"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// DBTokenStore 基于 zorm 和 cli_oauth 表实现 coreauth.Store 接口
type DBTokenStore struct{}

// NewDBTokenStore 创建数据库 Token 存储实例
func NewDBTokenStore() *DBTokenStore {
	return &DBTokenStore{}
}

// SetBaseDir 数据库存储不需要目录，空实现（满足 Manager 可选接口）
func (s *DBTokenStore) SetBaseDir(_ string) {}

// SkipFileAuth 标识该存储独立于文件系统管理 auth，Watcher 据此跳过文件扫描
func (s *DBTokenStore) SkipFileAuth() bool { return true }

// List 从 cli_oauth 表查询所有 auth 记录
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

// Save 将 auth 记录保存到 cli_oauth 表（存在则更新，不存在则插入）
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

	// 查询是否已存在
	existing, err := s.findByID(ctx, auth.ID)
	if err != nil {
		return "", fmt.Errorf("dbstore: 查询已有记录失败: %w", err)
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

// Delete 按 ID 从 cli_oauth 表删除记录
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

// findByID 按 ID 查询单条 cli_oauth 记录
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

// rowToAuth 将 CLIOauth 数据库记录转换为 *cliproxyauth.Auth
func (s *DBTokenStore) rowToAuth(item entity.CLIOauth) (*cliproxyauth.Auth, error) {
	metadata := make(map[string]any)
	if err := json.Unmarshal([]byte(item.Oauth), &metadata); err != nil {
		return nil, fmt.Errorf("dbstore: 解析 %s 的 oauth JSON 失败: %w", item.ID, err)
	}

	// 从 JSON 的 type 字段获取 provider，为空时通过 model_type 推导
	provider := strings.TrimSpace(valueAsString(metadata["type"]))
	if provider == "" {
		provider = modelTypeToProvider(item.ModelType)
	}

	disabled, _ := metadata["disabled"].(bool)
	status := cliproxyauth.StatusActive
	if disabled {
		status = cliproxyauth.StatusDisabled
	}

	// 设置 path 属性为 ID，buildAuthFileEntry 依赖非空 path 来构建返回结果
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

	if item.CreatedAt != nil {
		auth.CreatedAt = *item.CreatedAt
	}
	if item.UpdatedAt != nil {
		auth.UpdatedAt = *item.UpdatedAt
	}

	return auth, nil
}

// providerToModelType 将 provider 字符串映射为 model_type 整数
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

// modelTypeToProvider 将 model_type 整数反向映射为 provider 字符串
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
