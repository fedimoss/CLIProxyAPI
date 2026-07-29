package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"gitee.com/chunanyong/zorm"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/entity"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// DownloadAuthFile 按名称下载单个认证文件
func (h *Handler) DownloadAuthFile(c *gin.Context) {
	name := strings.TrimSpace(c.Query("name"))
	if isUnsafeAuthFileName(name) {
		c.JSON(400, gin.H{"error": "invalid name"})
		return
	}
	if !strings.HasSuffix(strings.ToLower(name), ".json") {
		c.JSON(400, gin.H{"error": "name must end with .json"})
		return
	}
	full := filepath.Join(h.cfg.AuthDir, name)
	data, err := os.ReadFile(full)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(404, gin.H{"error": "file not found"})
		} else {
			c.JSON(500, gin.H{"error": fmt.Sprintf("failed to read file: %v", err)})
		}
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", name))
	c.Data(200, "application/json", data)
}

// DownloadAuthData 从数据库下载认证数据
func (h *Handler) DownloadAuthData(c *gin.Context) {
	id := c.Query("name")
	if id == "" {
		c.JSON(400, gin.H{"error": "name is required"})
		return
	}
	ctx := c.Request.Context()
	finder := zorm.NewSelectFinder((&entity.CLIOauth{}).GetTableName())
	finder.Append(" where id=?", id)

	cLIOauth := &entity.CLIOauth{}
	if _, err := zorm.QueryRow(ctx, finder, cLIOauth); err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("query auth record failed: %v", err)})
		return
	}
	if cLIOauth.ID == "" {
		c.JSON(404, gin.H{"error": "auth not found"})
		return
	}
	oauthData := cLIOauth.Oauth
	fileName := id + ".json"
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fileName))
	c.Data(200, "application/octet-stream", []byte(oauthData))
}

// UploadAuthFile 上传认证文件：支持 multipart 或原始 JSON（带 ?name= 参数）
func (h *Handler) UploadAuthFile(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	ctx := c.Request.Context()

	fileHeaders, errMultipart := h.multipartAuthFileHeaders(c)
	if errMultipart != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid multipart form: %v", errMultipart)})
		return
	}
	if len(fileHeaders) == 1 {
		if _, errUpload := h.storeUploadedAuthFile(ctx, fileHeaders[0]); errUpload != nil {
			if errors.Is(errUpload, errAuthFileMustBeJSON) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "file must be .json"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": errUpload.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
		return
	}
	if len(fileHeaders) > 1 {
		uploaded := make([]string, 0, len(fileHeaders))
		failed := make([]gin.H, 0)
		for _, file := range fileHeaders {
			name, errUpload := h.storeUploadedAuthFile(ctx, file)
			if errUpload != nil {
				failureName := ""
				if file != nil {
					failureName = filepath.Base(file.Filename)
				}
				msg := errUpload.Error()
				if errors.Is(errUpload, errAuthFileMustBeJSON) {
					msg = "file must be .json"
				}
				failed = append(failed, gin.H{"name": failureName, "error": msg})
				continue
			}
			uploaded = append(uploaded, name)
		}
		if len(failed) > 0 {
			c.JSON(http.StatusMultiStatus, gin.H{
				"status":   "partial",
				"uploaded": len(uploaded),
				"files":    uploaded,
				"failed":   failed,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "uploaded": len(uploaded), "files": uploaded})
		return
	}
	if c.ContentType() == "multipart/form-data" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no files uploaded"})
		return
	}
	name := strings.TrimSpace(c.Query("name"))
	if isUnsafeAuthFileName(name) {
		c.JSON(400, gin.H{"error": "invalid name"})
		return
	}
	if !strings.HasSuffix(strings.ToLower(name), ".json") {
		c.JSON(400, gin.H{"error": "name must end with .json"})
		return
	}
	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	if err = h.writeAuthFile(ctx, filepath.Base(name), data); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "ok"})
}

// fileAuthSkipper 用于判断是否跳过文件认证
type fileAuthSkipper interface {
	SkipFileAuth() bool
}

func (h *Handler) shouldImportAuthUploadToDB() bool {
	if h == nil {
		return false
	}
	store := h.tokenStoreWithBaseDir()
	if store == nil {
		return false
	}
	if skipper, ok := store.(fileAuthSkipper); ok && skipper.SkipFileAuth() {
		return true
	}
	return false
}

// UploadAuthFileV2 上传认证文件（V2版本，支持导入到数据库）
func (h *Handler) UploadAuthFileV2(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	ctx := c.Request.Context()
	if !h.shouldImportAuthUploadToDB() {
		h.UploadAuthFile(c)
		return
	}
	ctx = PopulateAuthContext(ctx, c)
	if file, err := c.FormFile("file"); err == nil && file != nil {
		name := filepath.Base(file.Filename)
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			c.JSON(400, gin.H{"error": "file must be .json"})
			return
		}
		f, errOpen := file.Open()
		if errOpen != nil {
			c.JSON(400, gin.H{"error": "failed to open uploaded file"})
			return
		}
		defer func() { _ = f.Close() }()

		data, errRead := io.ReadAll(f)
		if errRead != nil {
			c.JSON(400, gin.H{"error": "failed to read uploaded file"})
			return
		}
		record, errBuild := buildAuthRecordFromJSON(data)
		if errBuild != nil {
			c.JSON(400, gin.H{"error": errBuild.Error()})
			return
		}
		oauthID, errSave := h.saveTokenRecord(ctx, record)
		if errSave != nil {
			c.JSON(500, gin.H{"error": errSave.Error()})
			return
		}
		c.JSON(200, gin.H{"status": "ok", "id": oauthID})
		return
	}
	//
	name := c.Query("name")
	if name == "" || strings.Contains(name, string(os.PathSeparator)) {
		c.JSON(400, gin.H{"error": "invalid name"})
		return
	}
	if !strings.HasSuffix(strings.ToLower(name), ".json") {
		c.JSON(400, gin.H{"error": "name must end with .json"})
		return
	}
	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	record, errBuild := buildAuthRecordFromJSON(data)
	if errBuild != nil {
		c.JSON(400, gin.H{"error": errBuild.Error()})
		return
	}
	oauthID, errSave := h.saveTokenRecord(ctx, record)
	if errSave != nil {
		c.JSON(500, gin.H{"error": errSave.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "ok", "id": oauthID})
}

// buildAuthRecordFromJSON 从JSON数据构建认证记录
func buildAuthRecordFromJSON(data []byte) (*coreauth.Auth, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty auth json")
	}
	metadata := make(map[string]any)
	if err := json.Unmarshal(trimmed, &metadata); err != nil {
		return nil, fmt.Errorf("invalid auth json: %w", err)
	}
	provider := strings.TrimSpace(valueAsString(metadata["type"]))
	if provider == "" {
		provider = "unknown"
		metadata["type"] = provider
	}
	label := provider
	if email := strings.TrimSpace(valueAsString(metadata["email"])); email != "" {
		label = email
	}
	disabled := false
	if v, ok := metadata["disabled"].(bool); ok {
		disabled = v
	}
	return &coreauth.Auth{
		Provider:  provider,
		Label:     label,
		Disabled:  disabled,
		Status:    coreauth.StatusActive,
		Metadata:  metadata,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

// DeleteAuthFile 删除认证文件：支持按名称删除单个文件或全部删除
func (h *Handler) DeleteAuthFile(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	ctx := c.Request.Context()
	if all := c.Query("all"); all == "true" || all == "1" || all == "*" {
		entries, err := os.ReadDir(h.cfg.AuthDir)
		if err != nil {
			c.JSON(500, gin.H{"error": fmt.Sprintf("failed to read auth dir: %v", err)})
			return
		}
		deleted := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(strings.ToLower(name), ".json") {
				continue
			}
			full := filepath.Join(h.cfg.AuthDir, name)
			if !filepath.IsAbs(full) {
				if abs, errAbs := filepath.Abs(full); errAbs == nil {
					full = abs
				}
			}
			if err = os.Remove(full); err == nil {
				if errDel := h.deleteTokenRecord(ctx, full); errDel != nil {
					c.JSON(500, gin.H{"error": errDel.Error()})
					return
				}
				deleted++
				h.removeAuth(ctx, full)
			}
		}
		c.JSON(200, gin.H{"status": "ok", "deleted": deleted})
		return
	}

	names, errNames := requestedAuthFileNamesForDelete(c)
	if errNames != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errNames.Error()})
		return
	}
	if len(names) == 0 {
		c.JSON(400, gin.H{"error": "invalid name"})
		return
	}
	if len(names) == 1 {
		if _, status, errDelete := h.deleteAuthFileByName(ctx, names[0]); errDelete != nil {
			c.JSON(status, gin.H{"error": errDelete.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
		return
	}

	deletedFiles := make([]string, 0, len(names))
	failed := make([]gin.H, 0)
	for _, name := range names {
		deletedName, _, errDelete := h.deleteAuthFileByName(ctx, name)
		if errDelete != nil {
			failed = append(failed, gin.H{"name": name, "error": errDelete.Error()})
			continue
		}
		deletedFiles = append(deletedFiles, deletedName)
	}
	if len(failed) > 0 {
		c.JSON(http.StatusMultiStatus, gin.H{
			"status":  "partial",
			"deleted": len(deletedFiles),
			"files":   deletedFiles,
			"failed":  failed,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "deleted": len(deletedFiles), "files": deletedFiles})
}

func (h *Handler) multipartAuthFileHeaders(c *gin.Context) ([]*multipart.FileHeader, error) {
	if h == nil || c == nil || c.ContentType() != "multipart/form-data" {
		return nil, nil
	}
	form, err := c.MultipartForm()
	if err != nil {
		return nil, err
	}
	if form == nil || len(form.File) == 0 {
		return nil, nil
	}

	keys := make([]string, 0, len(form.File))
	for key := range form.File {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	headers := make([]*multipart.FileHeader, 0)
	for _, key := range keys {
		headers = append(headers, form.File[key]...)
	}
	return headers, nil
}

func (h *Handler) storeUploadedAuthFile(ctx context.Context, file *multipart.FileHeader) (string, error) {
	if file == nil {
		return "", fmt.Errorf("no file uploaded")
	}
	name := filepath.Base(strings.TrimSpace(file.Filename))
	if !strings.HasSuffix(strings.ToLower(name), ".json") {
		return "", errAuthFileMustBeJSON
	}
	src, err := file.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open uploaded file: %w", err)
	}
	defer src.Close()

	data, err := io.ReadAll(src)
	if err != nil {
		return "", fmt.Errorf("failed to read uploaded file: %w", err)
	}
	if err := h.writeAuthFile(ctx, name, data); err != nil {
		return "", err
	}
	return name, nil
}

func (h *Handler) writeAuthFile(ctx context.Context, name string, data []byte) error {
	dst := filepath.Join(h.cfg.AuthDir, filepath.Base(name))
	if !filepath.IsAbs(dst) {
		if abs, errAbs := filepath.Abs(dst); errAbs == nil {
			dst = abs
		}
	}
	auth, err := h.buildAuthFromFileData(dst, data)
	if err != nil {
		return err
	}
	if errWrite := os.WriteFile(dst, data, 0o600); errWrite != nil {
		return fmt.Errorf("failed to write file: %w", errWrite)
	}
	if err := h.upsertAuthRecord(ctx, auth); err != nil {
		return err
	}
	return nil
}

func requestedAuthFileNamesForDelete(c *gin.Context) ([]string, error) {
	if c == nil {
		return nil, nil
	}
	names := uniqueAuthFileNames(c.QueryArray("name"))
	if len(names) > 0 {
		return names, nil
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body")
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, nil
	}

	var objectBody struct {
		Name  string   `json:"name"`
		Names []string `json:"names"`
	}
	if body[0] == '[' {
		var arrayBody []string
		if err := json.Unmarshal(body, &arrayBody); err != nil {
			return nil, fmt.Errorf("invalid request body")
		}
		return uniqueAuthFileNames(arrayBody), nil
	}
	if err := json.Unmarshal(body, &objectBody); err != nil {
		return nil, fmt.Errorf("invalid request body")
	}

	out := make([]string, 0, len(objectBody.Names)+1)
	if strings.TrimSpace(objectBody.Name) != "" {
		out = append(out, objectBody.Name)
	}
	out = append(out, objectBody.Names...)
	return uniqueAuthFileNames(out), nil
}

func uniqueAuthFileNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func (h *Handler) deleteAuthFileByName(ctx context.Context, name string) (string, int, error) {
	name = strings.TrimSpace(name)
	if isUnsafeAuthFileName(name) {
		return "", http.StatusBadRequest, fmt.Errorf("invalid name")
	}

	targetPath := filepath.Join(h.cfg.AuthDir, filepath.Base(name))
	targetID := ""
	if targetAuth := h.findAuthForDelete(name); targetAuth != nil {
		if !isPluginVirtualSourceDelete(name, targetAuth) {
			return filepath.Base(name), http.StatusConflict, errPluginVirtualAuth
		}
		targetID = strings.TrimSpace(targetAuth.ID)
		if path := strings.TrimSpace(authAttribute(targetAuth, "path")); path != "" {
			targetPath = path
		}
	}
	if !filepath.IsAbs(targetPath) {
		if abs, errAbs := filepath.Abs(targetPath); errAbs == nil {
			targetPath = abs
		}
	}
	if errRemove := os.Remove(targetPath); errRemove != nil {
		if os.IsNotExist(errRemove) {
			return filepath.Base(name), http.StatusNotFound, errAuthFileNotFound
		}
		return filepath.Base(name), http.StatusInternalServerError, fmt.Errorf("failed to remove file: %w", errRemove)
	}
	if errDeleteRecord := h.deleteTokenRecord(ctx, targetPath); errDeleteRecord != nil {
		return filepath.Base(name), http.StatusInternalServerError, errDeleteRecord
	}
	h.removeAuthsForPath(ctx, targetPath, targetID)
	return filepath.Base(name), http.StatusOK, nil
}

// DeleteAuthData 从数据库删除认证数据
func (h *Handler) DeleteAuthData(c *gin.Context) {
	ctx := c.Request.Context()
	allRaw := strings.TrimSpace(c.Query("all"))
	if allRaw == "" {
		allRaw = readAllParamFromBody(c)
	}
	if isTruthyFlag(allRaw) {
		reg := registry.GetGlobalRegistry()
		if h != nil && h.authManager != nil {
			for _, auth := range h.authManager.ListAll() {
				if isRuntimeOnlyAuth(auth) {
					continue
				}
				if auth != nil && strings.TrimSpace(auth.ID) != "" {
					reg.UnregisterClient(auth.ID)
				}
				h.removeAuth(ctx, auth.ID)
			}
		}

		if err := deleteOauthRecords(ctx, ""); err != nil {
			c.JSON(500, gin.H{"error": fmt.Sprintf("delete oauth records failed: %v", err)})
			return
		}
		c.JSON(200, gin.H{"status": "ok"})
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}

	var payload struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		c.JSON(400, gin.H{"error": "invalid request body"})
		return
	}

	names := uniqueAuthFileNames(payload.Names)
	if len(names) == 0 {
		c.JSON(400, gin.H{"error": "names is required"})
		return
	}
	failed := make([]gin.H, 0)
	deletedIDs := make([]string, 0, len(names))
	for _, name := range names {
		authID := name
		if target := h.findAuthForDelete(name); target != nil && strings.TrimSpace(target.ID) != "" {
			authID = strings.TrimSpace(target.ID)
		}
		registry.GetGlobalRegistry().UnregisterClient(authID)
		h.removeAuth(ctx, authID)

		if err := deleteOauthRecords(ctx, authID); err != nil {
			failed = append(failed, gin.H{"name": name, "error": err.Error()})
			continue
		}
		deletedIDs = append(deletedIDs, authID)
	}

	if len(failed) > 0 {
		c.JSON(http.StatusMultiStatus, gin.H{
			"status":  "partial",
			"deleted": len(deletedIDs),
			"names":   deletedIDs,
			"failed":  failed,
		})
		return
	}

	c.JSON(200, gin.H{"status": "ok", "deleted": len(deletedIDs), "names": deletedIDs})
}

func isTruthyFlag(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "*":
		return true
	default:
		return false
	}
}
func readAllParamFromBody(c *gin.Context) string {
	if c == nil {
		return ""
	}
	raw, errRead := c.GetRawData()
	if errRead != nil {
		return ""
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	c.Request.Body = io.NopCloser(bytes.NewBuffer(raw))
	if trimmed[0] == '{' {
		var payload struct {
			All any `json:"all"`
		}
		if errJSON := json.Unmarshal(trimmed, &payload); errJSON == nil {
			switch v := payload.All.(type) {
			case bool:
				if v {
					return "true"
				}
			case string:
				return strings.TrimSpace(v)
			case float64:
				if v != 0 {
					return "1"
				}
			}
		}
	}
	values, errParse := url.ParseQuery(string(trimmed))
	if errParse != nil {
		return ""
	}
	return strings.TrimSpace(values.Get("all"))
}
func deleteOauthRecords(ctx context.Context, id string) error {
	_, err := zorm.Transaction(ctx, func(txCtx context.Context) (interface{}, error) {
		userOauthFinder := zorm.NewDeleteFinder((&entity.CLIUserOauth{}).GetTableName())
		if strings.TrimSpace(id) != "" {
			userOauthFinder.Append(" where cli_oauth_id=?", id)
		}
		if _, errDel := zorm.UpdateFinder(txCtx, userOauthFinder); errDel != nil {
			return nil, fmt.Errorf("delete cli_user_oauth failed: %w", errDel)
		}

		oauthFinder := zorm.NewDeleteFinder((&entity.CLIOauth{}).GetTableName())
		if strings.TrimSpace(id) != "" {
			oauthFinder.Append(" where id=?", id)
		}
		if _, errDel := zorm.UpdateFinder(txCtx, oauthFinder); errDel != nil {
			return nil, fmt.Errorf("delete cli_oauth failed: %w", errDel)
		}
		return nil, nil
	})
	return err
}

func isPluginVirtualSourceDelete(name string, auth *coreauth.Auth) bool {
	if !coreauth.IsPluginVirtualAuth(auth) {
		return true
	}
	sourcePath := strings.TrimSpace(authAttribute(auth, coreauth.AttributeVirtualSource))
	if sourcePath == "" {
		sourcePath = strings.TrimSpace(authAttribute(auth, "path"))
	}
	if sourcePath == "" {
		return false
	}
	return strings.EqualFold(filepath.Base(strings.TrimSpace(name)), filepath.Base(sourcePath))
}

func (h *Handler) findAuthForDelete(name string) *coreauth.Auth {
	if h == nil || h.authManager == nil {
		return nil
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if auth, ok := h.authManager.GetByID(name); ok {
		return auth
	}
	auths := h.authManager.List()
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		if strings.TrimSpace(auth.FileName) == name {
			return auth
		}
		if filepath.Base(strings.TrimSpace(authAttribute(auth, "path"))) == name {
			return auth
		}
	}
	return nil
}

func (h *Handler) authIDForPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		if abs, errAbs := filepath.Abs(path); errAbs == nil {
			path = abs
		}
	}
	id := path
	if h != nil && h.cfg != nil {
		authDir := strings.TrimSpace(h.cfg.AuthDir)
		if resolvedAuthDir, errResolve := util.ResolveAuthDir(authDir); errResolve == nil && resolvedAuthDir != "" {
			authDir = resolvedAuthDir
		}
		if authDir != "" {
			authDir = filepath.Clean(authDir)
			if !filepath.IsAbs(authDir) {
				if abs, errAbs := filepath.Abs(authDir); errAbs == nil {
					authDir = abs
				}
			}
			if rel, errRel := filepath.Rel(authDir, path); errRel == nil && rel != "" {
				id = rel
			}
		}
	}
	// 在 Windows 上，规范化 ID 大小写，避免因路径不区分大小写导致重复的认证条目。
	if runtime.GOOS == "windows" {
		id = strings.ToLower(id)
	}
	return id
}

func (h *Handler) registerAuthFromFile(ctx context.Context, path string, data []byte) error {
	if h.authManager == nil {
		return nil
	}
	auth, err := h.buildAuthFromFileData(path, data)
	if err != nil {
		return err
	}
	return h.upsertAuthRecord(ctx, auth)
}

// buildAuthFromFileData 从文件路径和数据构建认证对象
func (h *Handler) buildAuthFromFileData(path string, data []byte) (*coreauth.Auth, error) {
	if path == "" {
		return nil, fmt.Errorf("auth path is empty")
	}
	if data == nil {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read auth file: %w", err)
		}
	}
	metadata := make(map[string]any)
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("invalid auth file: %w", err)
	}
	provider, _ := metadata["type"].(string)
	if provider == "" {
		provider = "unknown"
	}
	label := provider
	if email, ok := metadata["email"].(string); ok && email != "" {
		label = email
	}
	lastRefresh, hasLastRefresh := extractLastRefreshTimestamp(metadata)

	authID := h.authIDForPath(path)
	if authID == "" {
		authID = path
	}
	auth := (*coreauth.Auth)(nil)
	if h != nil && h.cfg != nil {
		sctx := &synthesizer.SynthesisContext{
			Config:      h.cfg,
			AuthDir:     h.cfg.AuthDir,
			Now:         time.Now(),
			IDGenerator: synthesizer.NewStableIDGenerator(),
		}
		if generated := synthesizer.SynthesizeAuthFile(sctx, path, data); len(generated) > 0 && generated[0] != nil {
			auth = generated[0].Clone()
		}
	}
	if auth == nil {
		auth = &coreauth.Auth{
			ID:       authID,
			Provider: provider,
			Label:    label,
			Status:   coreauth.StatusActive,
			Attributes: map[string]string{
				"path":   path,
				"source": path,
			},
			Metadata:  metadata,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
	}
	auth.ID = authID
	auth.FileName = filepath.Base(path)
	if hasLastRefresh {
		auth.LastRefreshedAt = lastRefresh
	}
	if h != nil && h.authManager != nil {
		if existing, ok := h.authManager.GetByID(authID); ok {
			auth.CreatedAt = existing.CreatedAt
			if !hasLastRefresh {
				auth.LastRefreshedAt = existing.LastRefreshedAt
			}
			auth.NextRefreshAfter = existing.NextRefreshAfter
			auth.Runtime = existing.Runtime
		}
	}
	coreauth.ApplyCustomHeadersFromMetadata(auth)
	return auth, nil
}

// upsertAuthRecord 插入或更新认证记录到管理器
func (h *Handler) upsertAuthRecord(ctx context.Context, auth *coreauth.Auth) error {
	if h == nil || h.authManager == nil || auth == nil {
		return nil
	}
	if existing, ok := h.authManager.GetByID(auth.ID); ok {
		auth.CreatedAt = existing.CreatedAt
		_, err := h.authManager.Update(ctx, auth)
		return err
	}
	_, err := h.authManager.Register(ctx, auth)
	return err
}
