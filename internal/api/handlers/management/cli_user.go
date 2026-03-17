package management

import (
	"context"
	"net/http"

	"gitee.com/chunanyong/zorm"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/entity"
)

// ListUsers 获取用户列表
// ListUsers GET /v0/management/users
func (h *Handler) ListUsers(c *gin.Context) {
	finder := zorm.NewSelectFinder((&entity.CLIUser{}).GetTableName())
	finder.Append("WHERE status != 3 ORDER BY id")

	var users []entity.CLIUser
	err := zorm.Query(context.Background(), finder, &users, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": users})
}

// AddUser 添加用户
// CreateUser POST /v0/management/users
func (h *Handler) CreateUser(c *gin.Context) {
	var req entity.CLIUser
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if req.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	if req.Status == 0 {
		req.Status = 1
	}

	_, err := zorm.Transaction(context.Background(), func(ctx context.Context) (interface{}, error) {
		return zorm.Insert(ctx, &req)
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "data": req})
}

// UpdateUser 更新用户
// UpdateUser PUT /v0/management/users
func (h *Handler) UpdateUser(c *gin.Context) {
	var req entity.CLIUser
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if req.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}

	_, err := zorm.Transaction(context.Background(), func(ctx context.Context) (interface{}, error) {
		return zorm.Update(ctx, &req)
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// DeleteUser 删除用户
// DeleteUser DELETE /v0/management/users
func (h *Handler) DeleteUser(c *gin.Context) {
	id := c.Query("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}

	finder := zorm.NewUpdateFinder((&entity.CLIUser{}).GetTableName())
	finder.Append("status=3 WHERE id=?", id)

	_, err := zorm.Transaction(context.Background(), func(ctx context.Context) (interface{}, error) {
		return zorm.UpdateFinder(ctx, finder)
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
