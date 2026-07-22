package cliproxy

import (
	"context"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/home"
	sdkpluginstore "github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginstore"
)

func TestSyncHomePluginsSkipsUnchangedSignature(t *testing.T) {
	cfg := &config.Config{}
	cfg.Home.Enabled = true
	cfg.Plugins.Enabled = true
	cfg.Plugins.Configs = map[string]config.PluginInstanceConfig{}

	service := &Service{homePluginSyncFetch: func(context.Context, sdkpluginstore.PluginSyncRequest) (sdkpluginstore.PluginSyncResponse, error) {
		return sdkpluginstore.PluginSyncResponse{
			SchemaVersion: sdkpluginstore.PluginSyncSchemaVersion,
			ExpiresAt:     time.Now().UTC().Add(time.Minute),
			Items:         []sdkpluginstore.PluginSyncItem{},
		}, nil
	}}
	report, key, didSync, errSync := service.syncHomePlugins(context.Background(), cfg)
	if errSync != nil {
		t.Fatalf("syncHomePlugins() error = %v", errSync)
	}
	if !didSync || key == "" || !report.OK {
		t.Fatalf("syncHomePlugins() didSync=%v key=%q report=%+v, want reportable empty plan", didSync, key, report)
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

func TestHomePluginSyncKeyIncludesCredentialRevision(t *testing.T) {
	cfg := &config.Config{}
	cfg.Home.Enabled = true
	cfg.Plugins.Enabled = true
	cfg.Plugins.Configs = map[string]config.PluginInstanceConfig{}
	first := homePluginSyncKey(cfg)
	cfg.Plugins.AuthRevision = 2
	second := homePluginSyncKey(cfg)
	if first == second {
		t.Fatalf("homePluginSyncKey() unchanged after sync revision update: %q", first)
	}
}

func TestForceHomeRuntimeConfigClearsStoreAuth(t *testing.T) {
	cfg := &config.Config{}
	cfg.Plugins.StoreAuth = []sdkpluginstore.AuthConfig{{
		Match: "https://downloads.example/", Type: sdkpluginstore.AuthTypeBearer, TokenEnv: "PLUGIN_TOKEN",
	}}
	forceHomeRuntimeConfig(cfg)
	if cfg.Plugins.StoreAuth != nil {
		t.Fatalf("Plugins.StoreAuth = %#v, want nil in Home mode", cfg.Plugins.StoreAuth)
	}
}
