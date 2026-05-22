package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitee.com/chunanyong/zorm"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/clioauth"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/entity"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// DBTokenStore 鍩轰簬鏁版嵁搴撶殑 Token 瀛樺偍瀹炵幇锛屾彁渚?OAuth 鍑嵁鐨勫鍒犳煡鏀规搷浣溿€?
type DBTokenStore struct{}

// NewDBTokenStore 鍒涘缓骞惰繑鍥炰竴涓柊鐨?DBTokenStore 瀹炰緥銆?
func NewDBTokenStore() *DBTokenStore {
	return &DBTokenStore{}
}

// SetBaseDir 璁剧疆鍩虹鐩綍锛堟暟鎹簱瀛樺偍妯″紡涓嬩笉浣跨敤锛岀┖瀹炵幇锛夈€?
func (s *DBTokenStore) SetBaseDir(_ string) {}

// SkipFileAuth 杩斿洖鏄惁璺宠繃鏂囦欢璁よ瘉锛屾暟鎹簱瀛樺偍妯″紡涓嬪缁堣繑鍥?true銆?
func (s *DBTokenStore) SkipFileAuth() bool { return true }

// List 浠庢暟鎹簱鏌ヨ鎵€鏈夎璇佽褰曘€?
func (s *DBTokenStore) List(ctx context.Context) ([]*cliproxyauth.Auth, error) {
	finder := zorm.NewSelectFinder((&entity.CLIOauth{}).GetTableName())
	finder.Append(" order by created_at desc")

	var authList []entity.CLIOauth
	if err := zorm.Query(ctx, finder, &authList, nil); err != nil {
		return nil, fmt.Errorf("dbstore: query auth failed: %w", err)
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

// Save 淇濆瓨璁よ瘉璁板綍鍒版暟鎹簱锛屽瓨鍦ㄥ垯鏇存柊锛屼笉瀛樺湪鍒欐彃鍏?
func (s *DBTokenStore) Save(ctx context.Context, auth *cliproxyauth.Auth) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("dbstore: auth is nil")
	}

	var oauthJSON []byte
	var err error
	if auth.Metadata != nil {
		oauthJSON, err = json.Marshal(auth.Metadata)
		if err != nil {
			return "", fmt.Errorf("dbstore: marshal metadata failed: %w", err)
		}
	} else {
		return "", fmt.Errorf("dbstore: %s has no serializable metadata", auth.ID)
	}

	now := time.Now()
	accountID := strings.TrimSpace(gjson.GetBytes(oauthJSON, "account_id").String())
	record := entity.CLIOauth{
		Oauth:     string(oauthJSON),
		ModelType: clioauth.ProviderToModelType(auth.Provider),
		UpdatedAt: &now,
		AccountID: accountID,
	}
	record.ID = auth.ID

	existing, err := s.findByID(ctx, auth.ID)
	if err != nil {
		return "", fmt.Errorf("dbstore: query existing record failed: %w", err)
	}
	status := cliproxyauth.DBStatusActive
	if existing != nil && existing.Status != 0 {
		status = cliproxyauth.NormalizeDBStatus(existing.Status)
	}
	status = cliproxyauth.DBStatusForAuth(auth)
	record.Status = status
	if status == cliproxyauth.DBStatusDisabled || status == cliproxyauth.DBStatusQuotaLimited {
		record.ErrorReason = disabledErrorReason(auth)
		if record.ErrorReason == "" && existing != nil {
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
		return "", fmt.Errorf("dbstore: save auth failed: %w", err)
	}

	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	if strings.TrimSpace(auth.FileName) == "" {
		auth.FileName = auth.ID
	}

	return auth.ID, nil
}

// Delete 鏍规嵁ID浠庢暟鎹簱鍒犻櫎璁よ瘉璁板綍
func (s *DBTokenStore) Delete(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("dbstore: id is empty")
	}

	finder := zorm.NewDeleteFinder((&entity.CLIOauth{}).GetTableName())
	finder.Append(" where id=?", id)

	_, err := zorm.Transaction(ctx, func(txCtx context.Context) (interface{}, error) {
		return zorm.UpdateFinder(txCtx, finder)
	})
	if err != nil {
		return fmt.Errorf("dbstore: delete auth failed: %w", err)
	}
	return nil
}

// findByID 鏍规嵁ID鏌ヨ璁よ瘉璁板綍
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

// rowToAuth 灏嗘暟鎹簱璁板綍杞崲涓鸿繍琛屾椂璁よ瘉瀵硅薄
func (s *DBTokenStore) rowToAuth(item entity.CLIOauth) (*cliproxyauth.Auth, error) {
	metadata := make(map[string]any)
	if err := json.Unmarshal([]byte(item.Oauth), &metadata); err != nil {
		return nil, fmt.Errorf("dbstore: parse oauth JSON for %s failed: %w", item.ID, err)
	}
	provider := strings.TrimSpace(valueAsString(metadata["type"]))
	if provider == "" {
		provider = clioauth.ModelTypeToProvider(item.ModelType)
	}

	// 灏嗘寔涔呭寲鐨勬暟鎹簱鐘舵€佽鑼冨寲锛屽苟鏄犲皠涓鸿繍琛屾椂鏍囧織銆?
	dbStatus := cliproxyauth.NormalizeDBStatus(item.Status)
	disabled := false
	unavailable := false
	status := cliproxyauth.StatusActive
	switch dbStatus {
	case cliproxyauth.DBStatusDisabled:
		disabled = true
		status = cliproxyauth.StatusDisabled
	case cliproxyauth.DBStatusQuotaLimited:
		status = cliproxyauth.StatusError
		unavailable = true
	default:
		if d, ok := metadata["disabled"].(bool); ok && d {
			disabled = true
			status = cliproxyauth.StatusDisabled
		}
	}
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
		DBStatus:         dbStatus,
		Disabled:         disabled,
		Unavailable:      unavailable,
		Attributes:       attr,
		Metadata:         metadata,
		LastRefreshedAt:  time.Time{},
		NextRefreshAfter: time.Time{},
	}
	if dbStatus == cliproxyauth.DBStatusQuotaLimited {
		// 鏁版嵁搴撶姸鎬?鏄彲鎭㈠鐨勶紝搴旀惡甯﹂厤棰濇爣璁般€?
		auth.Quota.Exceeded = true
		auth.Quota.Reason = "quota"
	}
	if disabled && strings.TrimSpace(item.ErrorReason) != "" {
		auth.LastError = &cliproxyauth.Error{
			Code:       "account_deactivated",
			Message:    strings.TrimSpace(item.ErrorReason),
			HTTPStatus: http.StatusUnauthorized,
		}
	} else if dbStatus == cliproxyauth.DBStatusQuotaLimited && strings.TrimSpace(item.ErrorReason) != "" {
		auth.LastError = &cliproxyauth.Error{
			Code:       "quota_limited",
			Message:    strings.TrimSpace(item.ErrorReason),
			HTTPStatus: http.StatusTooManyRequests,
		}
	}

	if item.CreatedAt != nil {
		auth.CreatedAt = *item.CreatedAt
	}
	if item.UpdatedAt != nil {
		auth.UpdatedAt = *item.UpdatedAt
	}
	if (disabled || dbStatus == cliproxyauth.DBStatusQuotaLimited) && strings.TrimSpace(item.ErrorReason) != "" {
		rawReason := strings.TrimSpace(item.ErrorReason)
		auth.StatusMessage = rawReason
	}

	return auth, nil
}
func disabledErrorReason(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.LastError != nil {
		if reason := strings.TrimSpace(auth.LastError.Message); reason != "" {
			return reason
		}
	}
	return ""
}
func providerToModelType(provider string) int {
	return clioauth.ProviderToModelType(provider)
}
func modelTypeToProvider(modelType int) string {
	return clioauth.ModelTypeToProvider(modelType)
}
