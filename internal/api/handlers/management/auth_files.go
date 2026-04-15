package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitee.com/chunanyong/zorm"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/clioauth"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/entity"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

var lastRefreshKeys = []string{"last_refresh", "lastRefresh", "last_refreshed_at", "lastRefreshedAt"}

const (
	anthropicCallbackPort = 54545
	geminiCallbackPort    = 8085
	codexCallbackPort     = 1455
)

// callbackForwarder 是OAuth回调的本地HTTP转发器
type callbackForwarder struct {
	provider string
	server   *http.Server
	done     chan struct{}
}

var (
	callbackForwardersMu  sync.Mutex
	callbackForwarders    = make(map[int]*callbackForwarder)
	errAuthFileMustBeJSON = errors.New("auth file must be .json")
	errAuthFileNotFound   = errors.New("auth file not found")
)

// extractLastRefreshTimestamp 从元数据中提取最近一次刷新时间戳
func extractLastRefreshTimestamp(meta map[string]any) (time.Time, bool) {
	if len(meta) == 0 {
		return time.Time{}, false
	}
	for _, key := range lastRefreshKeys {
		if val, ok := meta[key]; ok {
			if ts, ok1 := parseLastRefreshValue(val); ok1 {
				return ts, true
			}
		}
	}
	return time.Time{}, false
}

func parseLastRefreshValue(v any) (time.Time, bool) {
	switch val := v.(type) {
	case string:
		s := strings.TrimSpace(val)
		if s == "" {
			return time.Time{}, false
		}
		layouts := []string{time.RFC3339, time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02T15:04:05Z07:00"}
		for _, layout := range layouts {
			if ts, err := time.Parse(layout, s); err == nil {
				return ts.UTC(), true
			}
		}
		if unix, err := strconv.ParseInt(s, 10, 64); err == nil && unix > 0 {
			return time.Unix(unix, 0).UTC(), true
		}
	case float64:
		if val <= 0 {
			return time.Time{}, false
		}
		return time.Unix(int64(val), 0).UTC(), true
	case int64:
		if val <= 0 {
			return time.Time{}, false
		}
		return time.Unix(val, 0).UTC(), true
	case int:
		if val <= 0 {
			return time.Time{}, false
		}
		return time.Unix(int64(val), 0).UTC(), true
	case json.Number:
		if i, err := val.Int64(); err == nil && i > 0 {
			return time.Unix(i, 0).UTC(), true
		}
	}
	return time.Time{}, false
}

// isWebUIRequest 判断当前请求是否来自Web UI
func isWebUIRequest(c *gin.Context) bool {
	raw := strings.TrimSpace(c.Query("is_webui"))
	if raw == "" {
		return false
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// startCallbackForwarder 在本地端口启动HTTP服务器，将OAuth回调重定向到管理API
func startCallbackForwarder(port int, provider, targetBase string) (*callbackForwarder, error) {
	callbackForwardersMu.Lock()
	prev := callbackForwarders[port]
	if prev != nil {
		delete(callbackForwarders, port)
	}
	callbackForwardersMu.Unlock()

	if prev != nil {
		stopForwarderInstance(port, prev)
	}

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := targetBase
		if raw := r.URL.RawQuery; raw != "" {
			if strings.Contains(target, "?") {
				target = target + "&" + raw
			} else {
				target = target + "?" + raw
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target, http.StatusFound)
	})

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	done := make(chan struct{})

	go func() {
		if errServe := srv.Serve(ln); errServe != nil && !errors.Is(errServe, http.ErrServerClosed) {
			log.WithError(errServe).Warnf("callback forwarder for %s stopped unexpectedly", provider)
		}
		close(done)
	}()

	forwarder := &callbackForwarder{
		provider: provider,
		server:   srv,
		done:     done,
	}

	callbackForwardersMu.Lock()
	callbackForwarders[port] = forwarder
	callbackForwardersMu.Unlock()

	log.Infof("callback forwarder for %s listening on %s", provider, addr)

	return forwarder, nil
}

func stopCallbackForwarderInstance(port int, forwarder *callbackForwarder) {
	if forwarder == nil {
		return
	}
	callbackForwardersMu.Lock()
	if current := callbackForwarders[port]; current == forwarder {
		delete(callbackForwarders, port)
	}
	callbackForwardersMu.Unlock()

	stopForwarderInstance(port, forwarder)
}

func stopForwarderInstance(port int, forwarder *callbackForwarder) {
	if forwarder == nil || forwarder.server == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := forwarder.server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.WithError(err).Warnf("failed to shut down callback forwarder on port %d", port)
	}

	select {
	case <-forwarder.done:
	case <-time.After(2 * time.Second):
	}

	log.Infof("callback forwarder on port %d stopped", port)
}

// managementCallbackURL 构建管理API的回调URL
func (h *Handler) managementCallbackURL(path string) (string, error) {
	if h == nil || h.cfg == nil || h.cfg.Port <= 0 {
		return "", fmt.Errorf("server port is not configured")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	scheme := "http"
	if h.cfg.TLS.Enable {
		scheme = "https"
	}
	return fmt.Sprintf("%s://127.0.0.1:%d%s", scheme, h.cfg.Port, path), nil
}

// ListAuthFiles 返回所有认证文件列表
func (h *Handler) ListAuthFiles(c *gin.Context) {
	if h == nil {
		c.JSON(500, gin.H{"error": "handler not initialized"})
		return
	}

	if h.authManager == nil {
		h.listAuthFilesFromDisk(c)
		return
	}
	auths := h.authManager.List()
	files := make([]gin.H, 0, len(auths))
	for _, auth := range auths {
		if entry := h.buildAuthFileEntry(auth); entry != nil {
			files = append(files, entry)
		}
	}
	sort.Slice(files, func(i, j int) bool {
		nameI, _ := files[i]["name"].(string)
		nameJ, _ := files[j]["name"].(string)
		return strings.ToLower(nameI) < strings.ToLower(nameJ)
	})
	c.JSON(200, gin.H{"files": files})
}

// GetAuthFileModels 返回指定认证文件支持的模型列表
func (h *Handler) GetAuthFileModels(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(400, gin.H{"error": "name is required"})
		return
	}

	// 通过 authManager 查找认证 ID
	var authID string
	if h.authManager != nil {
		auths := h.authManager.List()
		for _, auth := range auths {
			if auth.FileName == name || auth.ID == name {
				authID = auth.ID
				break
			}
		}
	}

	if authID == "" {
		authID = name // 回退使用文件名作为ID
	}

	// 从注册中心获取模型列表
	reg := registry.GetGlobalRegistry()
	models := reg.GetModelsForClient(authID)

	result := make([]gin.H, 0, len(models))
	for _, m := range models {
		entry := gin.H{
			"id": m.ID,
		}
		if m.DisplayName != "" {
			entry["display_name"] = m.DisplayName
		}
		if m.Type != "" {
			entry["type"] = m.Type
		}
		if m.OwnedBy != "" {
			entry["owned_by"] = m.OwnedBy
		}
		result = append(result, entry)
	}

	c.JSON(200, gin.H{"models": result})
}

// listAuthFilesFromDisk 当认证管理器不可用时，从磁盘读取认证文件列表
func (h *Handler) listAuthFilesFromDisk(c *gin.Context) {
	entries, err := os.ReadDir(h.cfg.AuthDir)
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("failed to read auth dir: %v", err)})
		return
	}
	files := make([]gin.H, 0)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		if info, errInfo := e.Info(); errInfo == nil {
			fileData := gin.H{"name": name, "size": info.Size(), "modtime": info.ModTime()}

			// 读取文件以获取 type 字段
			full := filepath.Join(h.cfg.AuthDir, name)
			if data, errRead := os.ReadFile(full); errRead == nil {
				typeValue := gjson.GetBytes(data, "type").String()
				emailValue := gjson.GetBytes(data, "email").String()
				fileData["type"] = typeValue
				fileData["email"] = emailValue
				if pv := gjson.GetBytes(data, "priority"); pv.Exists() {
					switch pv.Type {
					case gjson.Number:
						fileData["priority"] = int(pv.Int())
					case gjson.String:
						if parsed, errAtoi := strconv.Atoi(strings.TrimSpace(pv.String())); errAtoi == nil {
							fileData["priority"] = parsed
						}
					}
				}
				if nv := gjson.GetBytes(data, "note"); nv.Exists() && nv.Type == gjson.String {
					if trimmed := strings.TrimSpace(nv.String()); trimmed != "" {
						fileData["note"] = trimmed
					}
				}
			}

			files = append(files, fileData)
		}
	}
	c.JSON(200, gin.H{"files": files})
}

// buildAuthFileEntry 构建认证文件的API响应条目
func (h *Handler) buildAuthFileEntry(auth *coreauth.Auth) gin.H {
	if auth == nil {
		return nil
	}
	auth.EnsureIndex()
	runtimeOnlyDetected := isRuntimeOnlyAuth(auth)
	path := strings.TrimSpace(authAttribute(auth, "path"))
	if path == "" && !runtimeOnlyDetected {
		return nil
	}
	name := strings.TrimSpace(auth.FileName)
	if name == "" {
		name = auth.ID
	}
	entry := gin.H{
		"id":             auth.ID,
		"auth_index":     auth.Index,
		"name":           name,
		"type":           strings.TrimSpace(auth.Provider),
		"provider":       strings.TrimSpace(auth.Provider),
		"label":          auth.Label,
		"status":         auth.Status,
		"status_message": auth.StatusMessage,
		"disabled":       auth.Disabled,
		"unavailable":    auth.Unavailable,
		"runtime_only":   false,
		"source":         "memory",
		"size":           int64(0),
	}
	if email := authEmail(auth); email != "" {
		entry["email"] = email
	}
	if accountType, account := auth.AccountInfo(); accountType != "" || account != "" {
		if accountType != "" {
			entry["account_type"] = accountType
		}
		if account != "" {
			entry["account"] = account
		}
	}
	if !auth.CreatedAt.IsZero() {
		entry["created_at"] = auth.CreatedAt
	}
	if !auth.UpdatedAt.IsZero() {
		entry["modtime"] = auth.UpdatedAt
		entry["updated_at"] = auth.UpdatedAt
	}
	if !auth.LastRefreshedAt.IsZero() {
		entry["last_refresh"] = auth.LastRefreshedAt
	}
	if !auth.NextRetryAfter.IsZero() {
		entry["next_retry_after"] = auth.NextRetryAfter
	}
	if path != "" {
		entry["path"] = path
		entry["source"] = "memory"
		entry["size"] = int64(0)
		ctx := context.Background()
		finder := zorm.NewSelectFinder((&entity.CLIOauth{}).GetTableName())
		finder.Append(" where id=?", path)
		tempRecord := &entity.CLIOauth{}
		_, errQuery := zorm.QueryRow(ctx, finder, tempRecord)
		recordExists := (errQuery == nil && tempRecord.ID != "")
		if !recordExists && coreauth.IsAuthDisabled(auth) {
			return nil
		}
	}
	if claims := extractCodexIDTokenClaims(auth); claims != nil {
		entry["id_token"] = claims
	}
	// 从 Attributes 中暴露 priority 字段（由合成器从 JSON "priority" 字段设置）。
	// 回退到 Metadata，用于通过 UploadAuthFile 注册的认证（无合成器）。
	if p := strings.TrimSpace(authAttribute(auth, "priority")); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			entry["priority"] = parsed
		}
	} else if auth.Metadata != nil {
		if rawPriority, ok := auth.Metadata["priority"]; ok {
			switch v := rawPriority.(type) {
			case float64:
				entry["priority"] = int(v)
			case int:
				entry["priority"] = v
			case string:
				if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					entry["priority"] = parsed
				}
			}
		}
	}
	// 从 Attributes 中暴露 note 字段（由合成器从 JSON "note" 字段设置）。
	// 回退到 Metadata，用于通过 UploadAuthFile 注册的认证（无合成器）。
	if note := strings.TrimSpace(authAttribute(auth, "note")); note != "" {
		entry["note"] = note
	} else if auth.Metadata != nil {
		if rawNote, ok := auth.Metadata["note"].(string); ok {
			if trimmed := strings.TrimSpace(rawNote); trimmed != "" {
				entry["note"] = trimmed
			}
		}
	}
	return entry
}

func extractCodexIDTokenClaims(auth *coreauth.Auth) gin.H {
	if auth == nil || auth.Metadata == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return nil
	}
	idTokenRaw, ok := auth.Metadata["id_token"].(string)
	if !ok {
		return nil
	}
	idToken := strings.TrimSpace(idTokenRaw)
	if idToken == "" {
		return nil
	}
	claims, err := codex.ParseJWTToken(idToken)
	if err != nil || claims == nil {
		return nil
	}

	result := gin.H{}
	if v := strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID); v != "" {
		result["chatgpt_account_id"] = v
	}
	if v := strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType); v != "" {
		result["plan_type"] = v
	}
	if v := claims.CodexAuthInfo.ChatgptSubscriptionActiveStart; v != nil {
		result["chatgpt_subscription_active_start"] = v
	}
	if v := claims.CodexAuthInfo.ChatgptSubscriptionActiveUntil; v != nil {
		result["chatgpt_subscription_active_until"] = v
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func authEmail(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["email"].(string); ok {
			return strings.TrimSpace(v)
		}
	}
	if auth.Attributes != nil {
		if v := strings.TrimSpace(auth.Attributes["email"]); v != "" {
			return v
		}
		if v := strings.TrimSpace(auth.Attributes["account_email"]); v != "" {
			return v
		}
	}
	return ""
}

func authAttribute(auth *coreauth.Auth, key string) string {
	if auth == nil || len(auth.Attributes) == 0 {
		return ""
	}
	return auth.Attributes[key]
}

func isRuntimeOnlyAuth(auth *coreauth.Auth) bool {
	if auth == nil || len(auth.Attributes) == 0 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(auth.Attributes["runtime_only"]), "true")
}

func isUnsafeAuthFileName(name string) bool {
	if strings.TrimSpace(name) == "" {
		return true
	}
	if strings.ContainsAny(name, "/\\") {
		return true
	}
	if filepath.VolumeName(name) != "" {
		return true
	}
	return false
}

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
				h.disableAuth(ctx, full)
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
	if targetID != "" {
		h.disableAuth(ctx, targetID)
	} else {
		h.disableAuth(ctx, targetPath)
	}
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
			for _, auth := range h.authManager.List() {
				if isRuntimeOnlyAuth(auth) {
					continue
				}
				if auth != nil && strings.TrimSpace(auth.ID) != "" {
					reg.UnregisterClient(auth.ID)
				}
				h.disableAuth(ctx, auth.ID)
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
		h.disableAuth(ctx, authID)

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
	attr := map[string]string{
		"path":   path,
		"source": path,
	}
	auth := &coreauth.Auth{
		ID:         authID,
		Provider:   provider,
		FileName:   filepath.Base(path),
		Label:      label,
		Status:     coreauth.StatusActive,
		Attributes: attr,
		Metadata:   metadata,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
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

// PatchAuthFileStatus 切换认证文件的禁用状态
func (h *Handler) PatchAuthFileStatus(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	var req struct {
		Name     string `json:"name"`
		Disabled *bool  `json:"disabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.Disabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "disabled is required"})
		return
	}

	ctx := c.Request.Context()

	// 通过名称或 ID 查找认证
	var targetAuth *coreauth.Auth
	if auth, ok := h.authManager.GetByID(name); ok {
		targetAuth = auth
	} else {
		auths := h.authManager.List()
		for _, auth := range auths {
			if auth.FileName == name {
				targetAuth = auth
				break
			}
		}
	}

	if targetAuth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth file not found"})
		return
	}

	// 通过共享的认证状态辅助函数更新禁用状态。
	if *req.Disabled {
		coreauth.ApplyManualDisabled(targetAuth, "disabled via management API", time.Now())
	} else {
		coreauth.ApplyManualEnabled(targetAuth, time.Now())
	}

	if _, err := h.authManager.Update(ctx, targetAuth); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update auth: %v", err)})
		return
	}

	// 刷新运行时模型注册行为，处理禁用/启用的状态切换。
	if *req.Disabled {
		// 禁用：立即从全局注册中心取消注册模型。
		registry.GetGlobalRegistry().UnregisterClient(targetAuth.ID)
	} else {
		// 启用：使用 postRegisterHook 重新填充运行时注册。
		if h.postRegisterHook != nil {
			h.postRegisterHook(ctx, targetAuth)
		}
	}

	// 保持数据库状态与运行时计算的数据库状态一致。
	finder := zorm.NewUpdateFinder((&entity.CLIOauth{}).GetTableName())
	status := coreauth.DBStatusForAuth(targetAuth)

	finder.Append("status=?, updated_at=?, error_reason=? where id=?", status, time.Now(), "", name)

	// 以事务方式持久化状态更新。
	_, err := zorm.Transaction(ctx, func(txCtx context.Context) (interface{}, error) {
		_, errUpdate := zorm.UpdateFinder(txCtx, finder)
		if errUpdate != nil {
			return nil, errUpdate
		}
		return nil, nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update auth: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "disabled": *req.Disabled})
}

// PatchAuthFileFields 更新认证文件的可编辑字段（prefix、proxy_url、headers、priority、note）。
func (h *Handler) PatchAuthFileFields(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	var req struct {
		Name     string            `json:"name"`
		Prefix   *string           `json:"prefix"`
		ProxyURL *string           `json:"proxy_url"`
		Headers  map[string]string `json:"headers"`
		Priority *int              `json:"priority"`
		Note     *string           `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	ctx := c.Request.Context()

	// 通过名称或 ID 查找认证
	var targetAuth *coreauth.Auth
	if auth, ok := h.authManager.GetByID(name); ok {
		targetAuth = auth
	} else {
		auths := h.authManager.List()
		for _, auth := range auths {
			if auth.FileName == name {
				targetAuth = auth
				break
			}
		}
	}

	if targetAuth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth file not found"})
		return
	}

	changed := false
	if req.Prefix != nil {
		prefix := strings.TrimSpace(*req.Prefix)
		targetAuth.Prefix = prefix
		if targetAuth.Metadata == nil {
			targetAuth.Metadata = make(map[string]any)
		}
		if prefix == "" {
			delete(targetAuth.Metadata, "prefix")
		} else {
			targetAuth.Metadata["prefix"] = prefix
		}
		changed = true
	}
	if req.ProxyURL != nil {
		proxyURL := strings.TrimSpace(*req.ProxyURL)
		targetAuth.ProxyURL = proxyURL
		if targetAuth.Metadata == nil {
			targetAuth.Metadata = make(map[string]any)
		}
		if proxyURL == "" {
			delete(targetAuth.Metadata, "proxy_url")
		} else {
			targetAuth.Metadata["proxy_url"] = proxyURL
		}
		changed = true
	}
	if len(req.Headers) > 0 {
		existingHeaders := coreauth.ExtractCustomHeadersFromMetadata(targetAuth.Metadata)
		nextHeaders := make(map[string]string, len(existingHeaders))
		for k, v := range existingHeaders {
			nextHeaders[k] = v
		}
		headerChanged := false

		for key, value := range req.Headers {
			name := strings.TrimSpace(key)
			if name == "" {
				continue
			}
			val := strings.TrimSpace(value)
			attrKey := "header:" + name
			if val == "" {
				if _, ok := nextHeaders[name]; ok {
					delete(nextHeaders, name)
					headerChanged = true
				}
				if targetAuth.Attributes != nil {
					if _, ok := targetAuth.Attributes[attrKey]; ok {
						headerChanged = true
					}
				}
				continue
			}
			if prev, ok := nextHeaders[name]; !ok || prev != val {
				headerChanged = true
			}
			nextHeaders[name] = val
			if targetAuth.Attributes != nil {
				if prev, ok := targetAuth.Attributes[attrKey]; !ok || prev != val {
					headerChanged = true
				}
			} else {
				headerChanged = true
			}
		}

		if headerChanged {
			if targetAuth.Metadata == nil {
				targetAuth.Metadata = make(map[string]any)
			}
			if targetAuth.Attributes == nil {
				targetAuth.Attributes = make(map[string]string)
			}

			for key, value := range req.Headers {
				name := strings.TrimSpace(key)
				if name == "" {
					continue
				}
				val := strings.TrimSpace(value)
				attrKey := "header:" + name
				if val == "" {
					delete(nextHeaders, name)
					delete(targetAuth.Attributes, attrKey)
					continue
				}
				nextHeaders[name] = val
				targetAuth.Attributes[attrKey] = val
			}

			if len(nextHeaders) == 0 {
				delete(targetAuth.Metadata, "headers")
			} else {
				metaHeaders := make(map[string]any, len(nextHeaders))
				for k, v := range nextHeaders {
					metaHeaders[k] = v
				}
				targetAuth.Metadata["headers"] = metaHeaders
			}
			changed = true
		}
	}
	if req.Priority != nil || req.Note != nil {
		if targetAuth.Metadata == nil {
			targetAuth.Metadata = make(map[string]any)
		}
		if targetAuth.Attributes == nil {
			targetAuth.Attributes = make(map[string]string)
		}

		if req.Priority != nil {
			if *req.Priority == 0 {
				delete(targetAuth.Metadata, "priority")
				delete(targetAuth.Attributes, "priority")
			} else {
				targetAuth.Metadata["priority"] = *req.Priority
				targetAuth.Attributes["priority"] = strconv.Itoa(*req.Priority)
			}
		}
		if req.Note != nil {
			trimmedNote := strings.TrimSpace(*req.Note)
			if trimmedNote == "" {
				delete(targetAuth.Metadata, "note")
				delete(targetAuth.Attributes, "note")
			} else {
				targetAuth.Metadata["note"] = trimmedNote
				targetAuth.Attributes["note"] = trimmedNote
			}
		}
		changed = true
	}

	if !changed {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	targetAuth.UpdatedAt = time.Now()

	if _, err := h.authManager.Update(ctx, targetAuth); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update auth: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) disableAuth(ctx context.Context, id string) {
	if h == nil || h.authManager == nil {
		return
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	if auth, ok := h.authManager.GetByID(id); ok {
		coreauth.ApplyManualDisabled(auth, "removed via management API", time.Now())
		_, _ = h.authManager.Update(ctx, auth)
		return
	}
	authID := h.authIDForPath(id)
	if authID == "" {
		return
	}
	if auth, ok := h.authManager.GetByID(authID); ok {
		coreauth.ApplyManualDisabled(auth, "removed via management API", time.Now())
		_, _ = h.authManager.Update(ctx, auth)
	}
}

func (h *Handler) deleteTokenRecord(ctx context.Context, path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("auth path is empty")
	}
	store := h.tokenStoreWithBaseDir()
	if store == nil {
		return fmt.Errorf("token store unavailable")
	}
	return store.Delete(ctx, path)
}

func (h *Handler) tokenStoreWithBaseDir() coreauth.Store {
	if h == nil {
		return nil
	}
	store := h.tokenStore
	if store == nil {
		store = sdkAuth.GetTokenStore()
		h.tokenStore = store
	}
	if h.cfg != nil {
		if dirSetter, ok := store.(interface{ SetBaseDir(string) }); ok {
			dirSetter.SetBaseDir(h.cfg.AuthDir)
		}
	}
	return store
}

func (h *Handler) saveTokenRecord(ctx context.Context, record *coreauth.Auth) (string, error) {
	if record == nil {
		return "", fmt.Errorf("token record is nil")
	}
	store := h.tokenStoreWithBaseDir()
	if store == nil {
		return "", fmt.Errorf("token store unavailable")
	}
	if h.postAuthHook != nil {
		if err := h.postAuthHook(ctx, record); err != nil {
			return "", fmt.Errorf("post-auth hook failed: %w", err)
		}
	}

	// 将 OAuth 令牌序列化为 JSON（内容与原始 JSON 文件相同）
	var oauthJSON []byte
	var err error
	switch {
	case record.Storage != nil:
		type metadataGetter interface {
			SetMetadata(map[string]any)
		}
		if setter, ok := record.Storage.(metadataGetter); ok && record.Metadata != nil {
			setter.SetMetadata(record.Metadata)
		}
		merged, errMerge := misc.MergeMetadata(record.Storage, record.Metadata)
		if errMerge != nil {
			return "", fmt.Errorf("merge metadata failed: %w", errMerge)
		}
		// Ensure the "type" field is set, mirroring what each SaveTokenToFile() does.
		// The struct's Type field may be zero-valued (""), so override it with the provider name.
		if record.Provider != "" {
			merged["type"] = record.Provider
		}
		oauthJSON, err = json.Marshal(merged)
		if err != nil {
			return "", fmt.Errorf("marshal oauth token failed: %w", err)
		}
	case record.Metadata != nil:
		// Mirror filestore.Save: inject "disabled" into metadata before marshalling.
		record.Metadata["disabled"] = record.Disabled
		oauthJSON, err = json.Marshal(record.Metadata)
		if err != nil {
			return "", fmt.Errorf("marshal oauth metadata failed: %w", err)
		}
	default:
		return "", fmt.Errorf("nothing to persist for %s", record.ID)
	}

	// Determine model type from provider
	modelType := clioauth.ProviderToModelType(record.Provider)
	now := time.Now()
	oauthID := fmt.Sprintf("oauth_%d", now.UnixNano())
	cliUserID := config.DefaultCLIUserID
	if h != nil && h.cfg != nil {
		if v := strings.TrimSpace(h.cfg.CLIUserID); v != "" {
			cliUserID = v
		}
	}
	if reqInfo := coreauth.GetRequestInfo(ctx); reqInfo != nil {
		if uid := strings.TrimSpace(reqInfo.Query.Get("cli_user_id")); uid != "" {
			cliUserID = uid
		}
	}
	accountID := ""
	if modelType == 1 {
		accountID = strings.TrimSpace(gjson.GetBytes(oauthJSON, "account_id").String())
		if accountID == "" {
		}
		if accountID == "" {
			return "", fmt.Errorf("model_type=1 missing account_id, unable to persist")
		}
		type existingOauthRow struct {
			ID        string     `column:"id"`
			Status    int        `column:"status"`
			CreatedAt *time.Time `column:"created_at"`
		}
		finder := zorm.NewSelectFinder("cli_oauth o join cli_user_oauth uo on o.id = uo.cli_oauth_id", "o.id, o.status, o.created_at")
		finder.Append("where o.model_type=? and o.account_id=? and uo.cli_user_id=?", modelType, accountID, cliUserID)
		finder.Append("limit 1")

		var rows []*existingOauthRow
		if errQuery := zorm.Query(ctx, finder, &rows, nil); errQuery != nil {
			return "", fmt.Errorf("query existing oauth by account_id failed: %w", errQuery)
		}
		if len(rows) > 0 && rows[0] != nil && strings.TrimSpace(rows[0].ID) != "" {
			existingID := strings.TrimSpace(rows[0].ID)
			_, errUpdate := zorm.Transaction(ctx, func(txCtx context.Context) (interface{}, error) {
				updateFinder := zorm.NewUpdateFinder((&entity.CLIOauth{}).GetTableName())
				updateFinder.Append("oauth=?, updated_at=?, account_id=?, error_reason=? where id=?", string(oauthJSON), now, accountID, "", existingID)
				if _, errExec := zorm.UpdateFinder(txCtx, updateFinder); errExec != nil {
					return nil, fmt.Errorf("update cli_oauth failed: %w", errExec)
				}
				return nil, nil
			})
			if errUpdate != nil {
				return "", fmt.Errorf("update existing oauth failed: %w", errUpdate)
			}

			log.Infof("OAuth updated in database: cli_oauth.id=%s, cli_user_id=%s, provider=%s, account_id=%s", existingID, cliUserID, record.Provider, accountID)
			if h.authManager != nil {
				fullMetadata := make(map[string]any)
				if errUnmarshal := json.Unmarshal(oauthJSON, &fullMetadata); errUnmarshal != nil {
					log.Warnf("OAuth updated in DB but failed to unmarshal for cache: %v", errUnmarshal)
					return existingID, nil
				}

				regCtx := coreauth.WithSkipPersist(ctx)
				if cached, ok := h.authManager.GetByID(existingID); ok && cached != nil {
					cached.Provider = record.Provider
					cached.Label = record.Label
					cached.Storage = record.Storage
					cached.Metadata = fullMetadata
					cached.UpdatedAt = now
					if cached.Attributes == nil {
						cached.Attributes = make(map[string]string)
					}
					cached.Attributes["path"] = existingID
					if email := strings.TrimSpace(valueAsString(fullMetadata["email"])); email != "" {
						cached.Attributes["email"] = email
					}

					if _, errUpdateMem := h.authManager.Update(regCtx, cached); errUpdateMem != nil {
						log.Warnf("OAuth updated in DB but failed to update in memory: %v", errUpdateMem)
					} else if h.postRegisterHook != nil {
						h.postRegisterHook(regCtx, cached)
					}
				} else {
					dbStatus := coreauth.NormalizeDBStatus(rows[0].Status)
					disabled := false
					status := coreauth.StatusActive
					unavailable := false
					switch dbStatus {
					case coreauth.DBStatusDisabled:
						disabled = true
						status = coreauth.StatusDisabled
					case coreauth.DBStatusQuotaLimited:
						status = coreauth.StatusError
						unavailable = true
					}
					createdAt := now
					if rows[0].CreatedAt != nil && !rows[0].CreatedAt.IsZero() {
						createdAt = *rows[0].CreatedAt
					}

					cacheRecord := &coreauth.Auth{
						ID:          existingID,
						Provider:    record.Provider,
						FileName:    existingID,
						Label:       record.Label,
						Status:      status,
						DBStatus:    dbStatus,
						Disabled:    disabled,
						Unavailable: unavailable,
						Storage:     record.Storage,
						Metadata:    fullMetadata,
						CreatedAt:   createdAt,
						UpdatedAt:   now,
						Attributes: map[string]string{
							"path": existingID,
						},
					}
					if email := strings.TrimSpace(valueAsString(fullMetadata["email"])); email != "" {
						cacheRecord.Attributes["email"] = email
					}
					if _, errReg := h.authManager.Register(regCtx, cacheRecord); errReg != nil {
						log.Warnf("OAuth updated in DB but failed to register in memory: %v", errReg)
					} else if h.postRegisterHook != nil {
						h.postRegisterHook(regCtx, cacheRecord)
					}
				}
			}

			return existingID, nil
		}
	}

	// Save to cli_oauth and cli_user_oauth in a single transaction
	_, err = zorm.Transaction(ctx, func(txCtx context.Context) (interface{}, error) {
		// Insert cli_oauth record
		oauthRecord := &entity.CLIOauth{
			ID:          oauthID,
			Oauth:       string(oauthJSON),
			ModelType:   modelType,
			AccountID:   accountID,
			ErrorReason: "",
			Status:      1,
			CreatedAt:   &now,
			UpdatedAt:   &now,
		}
		if _, errInsert := zorm.Insert(txCtx, oauthRecord); errInsert != nil {
			return nil, fmt.Errorf("insert cli_oauth failed: %w", errInsert)
		}

		// Insert cli_user_oauth record
		userOauthID := fmt.Sprintf("uo_%d", now.UnixNano())
		userOauthRecord := &entity.CLIUserOauth{
			ID:         userOauthID,
			CliUserId:  cliUserID,
			CliOauthId: oauthID,
		}
		if _, errInsert := zorm.Insert(txCtx, userOauthRecord); errInsert != nil {
			return nil, fmt.Errorf("insert cli_user_oauth failed: %w", errInsert)
		}

		return nil, nil
	})
	if err != nil {
		return "", fmt.Errorf("save oauth to database failed: %w", err)
	}

	log.Infof("OAuth saved to database: cli_oauth.id=%s, cli_user_id=%s, provider=%s", oauthID, cliUserID, record.Provider)
	if h.authManager != nil {
		fullMetadata := make(map[string]any)
		if errUnmarshal := json.Unmarshal(oauthJSON, &fullMetadata); errUnmarshal != nil {
			log.Warnf("OAuth saved to DB but failed to unmarshal for cache: %v", errUnmarshal)
			return oauthID, nil
		}

		cacheRecord := &coreauth.Auth{
			ID:        oauthID,
			Provider:  record.Provider,
			FileName:  oauthID,
			Label:     record.Label,
			Status:    record.Status,
			Disabled:  record.Disabled,
			Storage:   record.Storage,
			Metadata:  fullMetadata,
			CreatedAt: now,
			UpdatedAt: now,
			Attributes: map[string]string{
				"path": oauthID,
			},
		}
		if email := strings.TrimSpace(valueAsString(fullMetadata["email"])); email != "" {
			cacheRecord.Attributes["email"] = email
		}
		regCtx := coreauth.WithSkipPersist(ctx)
		if _, errReg := h.authManager.Register(regCtx, cacheRecord); errReg != nil {
			log.Warnf("OAuth saved to DB but failed to register in memory: %v", errReg)
		} else if h.postRegisterHook != nil {
			h.postRegisterHook(regCtx, cacheRecord)
		}
	}

	return oauthID, nil
}
