package cliproxy

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/home"
)

func TestSyncHomePluginsSkipsUnchangedSignature(t *testing.T) {
	cfg := &config.Config{}
	cfg.Home.Enabled = true
	cfg.Plugins.Enabled = true
	cfg.Plugins.Configs = map[string]config.PluginInstanceConfig{}

	service := &Service{}
	_, key, didSync, errSync := service.syncHomePlugins(context.Background(), cfg)
	if errSync != nil {
		t.Fatalf("syncHomePlugins() error = %v", errSync)
	}
	if !didSync || key == "" {
		t.Fatalf("syncHomePlugins() didSync=%v key=%q, want first sync with key", didSync, key)
	}
	service.markHomePluginsSynced(key)

	_, gotKey, didSync, errSync := service.syncHomePlugins(context.Background(), cfg)
	if errSync != nil {
		t.Fatalf("syncHomePlugins(second) error = %v", errSync)
	}
	if didSync || gotKey != key {
		t.Fatalf("syncHomePlugins(second) didSync=%v key=%q, want skipped same key %q", didSync, gotKey, key)
	}
}

func TestApplyHomeOverlayAppliesMergedConfig(t *testing.T) {
	base := &config.Config{}
	base.Home.Enabled = true
	base.Plugins.Enabled = true
	service := &Service{cfg: base}

	// applyHomeOverlay merges the remote config into the base (preserving the
	// base Host/Port/TLS/Home) and applies it. It no longer synchronizes
	// plugins, so a remote config cannot trigger a plugin-sync failure here.
	remote := &config.Config{}
	remote.Plugins.Enabled = true
	remote.Plugins.Configs = map[string]config.PluginInstanceConfig{}

	service.applyHomeOverlay(remote)

	if service.cfg == nil || !service.cfg.Home.Enabled {
		t.Fatalf("service cfg = %+v, want base home config preserved after overlay", service.cfg)
	}
	if service.cfg == nil || !service.cfg.Plugins.Enabled {
		t.Fatalf("service cfg = %+v, want remote plugins config applied by overlay", service.cfg)
	}
	if service.homePluginSyncKey != "" {
		t.Fatalf("homePluginSyncKey = %q, want empty; applyHomeOverlay does not sync plugins", service.homePluginSyncKey)
	}
}

func TestStartHomeSubscriberDoesNotPreMarkPluginSync(t *testing.T) {
	cfg := &config.Config{}
	cfg.Home.Enabled = true
	cfg.Home.Host = "127.0.0.1"
	cfg.Home.Port = 1
	cfg.Plugins.Enabled = true
	cfg.Plugins.Configs = map[string]config.PluginInstanceConfig{}
	service := &Service{cfg: cfg}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service.startHomeSubscriber(ctx)
	defer func() {
		home.ClearCurrent()
		if service.homeCancel != nil {
			service.homeCancel()
		}
		if service.homeClient != nil {
			service.homeClient.Close()
		}
	}()

	if service.homePluginSyncKey != "" {
		t.Fatalf("homePluginSyncKey = %q, want empty before a successful plugin sync", service.homePluginSyncKey)
	}
}
