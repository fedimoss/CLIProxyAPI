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

// DBTokenStore stores OAuth auth records in the database.
type DBTokenStore struct{}

// NewDBTokenStore creates a DB-backed token store.
func NewDBTokenStore() *DBTokenStore {
	return &DBTokenStore{}
}

// SetBaseDir is a no-op for database-backed storage.
func (s *DBTokenStore) SetBaseDir(_ string) {}

// SkipFileAuth reports that file auth scanning should be skipped in DB mode.
func (s *DBTokenStore) SkipFileAuth() bool { return true }

// List returns all OAuth auth records from the database.
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

// Save inserts or updates an auth record.
func (s *DBTokenStore) Save(ctx context.Context, auth *cliproxyauth.Auth) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("dbstore: auth is nil")
	}
	if auth.Metadata == nil {
		return "", fmt.Errorf("dbstore: %s has no serializable metadata", auth.ID)
	}
	oauthJSON, errMarshal := json.Marshal(auth.Metadata)
	if errMarshal != nil {
		return "", fmt.Errorf("dbstore: marshal metadata failed: %w", errMarshal)
	}

	now := time.Now()
	accountID := strings.TrimSpace(gjson.GetBytes(oauthJSON, "account_id").String())
	record := entity.CLIOauth{
		ID:        auth.ID,
		Oauth:     string(oauthJSON),
		ModelType: clioauth.ProviderToModelType(auth.Provider),
		UpdatedAt: &now,
		AccountID: accountID,
	}

	existing, errFind := s.findByID(ctx, auth.ID)
	if errFind != nil {
		return "", fmt.Errorf("dbstore: query existing record failed: %w", errFind)
	}
	status := cliproxyauth.DBStatusForAuth(auth)
	record.Status = status
	if status == cliproxyauth.DBStatusDisabled || status == cliproxyauth.DBStatusQuotaLimited {
		record.ErrorReason = disabledErrorReason(auth)
		if record.ErrorReason == "" && existing != nil {
			record.ErrorReason = strings.TrimSpace(existing.ErrorReason)
		}
	}

	_, errTx := zorm.Transaction(ctx, func(txCtx context.Context) (interface{}, error) {
		if existing != nil {
			record.CreatedAt = existing.CreatedAt
			return zorm.Update(txCtx, &record)
		}
		record.CreatedAt = &now
		return zorm.Insert(txCtx, &record)
	})
	if errTx != nil {
		return "", fmt.Errorf("dbstore: save auth failed: %w", errTx)
	}

	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	if strings.TrimSpace(auth.FileName) == "" {
		auth.FileName = auth.ID
	}
	return auth.ID, nil
}

// Delete removes an auth record by ID.
func (s *DBTokenStore) Delete(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("dbstore: id is empty")
	}

	finder := zorm.NewDeleteFinder((&entity.CLIOauth{}).GetTableName())
	finder.Append(" where id=?", id)

	_, errTx := zorm.Transaction(ctx, func(txCtx context.Context) (interface{}, error) {
		return zorm.UpdateFinder(txCtx, finder)
	})
	if errTx != nil {
		return fmt.Errorf("dbstore: delete auth failed: %w", errTx)
	}
	return nil
}

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

func (s *DBTokenStore) rowToAuth(item entity.CLIOauth) (*cliproxyauth.Auth, error) {
	metadata := make(map[string]any)
	if err := json.Unmarshal([]byte(item.Oauth), &metadata); err != nil {
		return nil, fmt.Errorf("dbstore: parse oauth JSON for %s failed: %w", item.ID, err)
	}
	provider := strings.TrimSpace(valueAsString(metadata["type"]))
	if provider == "" {
		provider = clioauth.ModelTypeToProvider(item.ModelType)
	}

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
		if disabledMeta, _ := metadata["disabled"].(bool); disabledMeta {
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
		auth.StatusMessage = strings.TrimSpace(item.ErrorReason)
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
