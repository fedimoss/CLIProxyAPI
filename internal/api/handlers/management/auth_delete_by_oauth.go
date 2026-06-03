package management

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"gitee.com/chunanyong/zorm"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/entity"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	log "github.com/sirupsen/logrus"
)

// DeleteAuthByOAuth deletes auth records whose oauth column matches the
// given keyword with SQL LIKE.  It removes the records from the database,
// unregisters the associated models from the global registry and purges the
// auth from the in-memory cache.
//
// Query param: keyword (required) — the substring to match against cli_oauth.oauth.
//
// This handler is intentionally standalone: it does not reuse any existing
// helper methods so that future upstream merges remain conflict-free.
func (h *Handler) DeleteAuthByOAuth(c *gin.Context) {
	keyword := strings.TrimSpace(c.Query("keyword"))
	if keyword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "keyword is required"})
		return
	}

	ctx := c.Request.Context()

	// --- Step 1: LIKE query on cli_oauth.oauth ---
	finder := zorm.NewSelectFinder((&entity.CLIOauth{}).GetTableName())
	finder.Append(" WHERE oauth LIKE ?", "%"+keyword+"%")

	var matched []entity.CLIOauth
	if err := zorm.Query(ctx, finder, &matched, nil); err != nil {
		log.Errorf("DeleteAuthByOAuth: query failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("query failed: %v", err)})
		return
	}

	if len(matched) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"status": "not_found", "deleted": 0})
		return
	}

	// --- Step 2: For each match, remove from memory + registry + database ---
	deletedIDs := make([]string, 0, len(matched))
	failed := make([]gin.H, 0)

	for _, record := range matched {
		id := strings.TrimSpace(record.ID)
		if id == "" {
			continue
		}

		// 2a. Unregister models from the global model registry.
		registry.GetGlobalRegistry().UnregisterClient(id)

		// 2b. Remove from the in-memory auth cache (active + inactive + scheduler).
		if h.authManager != nil {
			h.authManager.Remove(id)
		}

		// 2c. Delete from database in a transaction (foreign key safe).
		if err := deleteOauthRecordByID(ctx, id); err != nil {
			log.Errorf("DeleteAuthByOAuth: delete record %s failed: %v", id, err)
			failed = append(failed, gin.H{"id": id, "error": err.Error()})
			continue
		}

		deletedIDs = append(deletedIDs, id)
		log.Infof("DeleteAuthByOAuth: deleted auth %s (matched keyword %q)", id, keyword)
	}

	if len(failed) > 0 {
		c.JSON(http.StatusMultiStatus, gin.H{
			"status":  "partial",
			"deleted": len(deletedIDs),
			"ids":     deletedIDs,
			"failed":  failed,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"deleted": len(deletedIDs),
		"ids":     deletedIDs,
	})
}

// deleteOauthRecordByID removes a single auth record and its user-oauth
// relationship rows from the database.  This is a standalone helper used only
// by DeleteAuthByOAuth to avoid coupling with the existing deleteOauthRecords.
func deleteOauthRecordByID(ctx context.Context, id string) error {
	_, err := zorm.Transaction(ctx, func(txCtx context.Context) (interface{}, error) {
		// Remove foreign-key rows first.
		uf := zorm.NewDeleteFinder((&entity.CLIUserOauth{}).GetTableName())
		uf.Append(" WHERE cli_oauth_id=?", id)
		if _, errDel := zorm.UpdateFinder(txCtx, uf); errDel != nil {
			return nil, fmt.Errorf("delete cli_user_oauth for %s: %w", id, errDel)
		}

		// Remove the auth row itself.
		of := zorm.NewDeleteFinder((&entity.CLIOauth{}).GetTableName())
		of.Append(" WHERE id=?", id)
		if _, errDel := zorm.UpdateFinder(txCtx, of); errDel != nil {
			return nil, fmt.Errorf("delete cli_oauth for %s: %w", id, errDel)
		}
		return nil, nil
	})
	return err
}
