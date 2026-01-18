package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

type ServicePrincipal struct {
	TenantID     string `toml:"tenant_id"`
	ClientID     string `toml:"client_id"`
	ClientSecret string `toml:"client_secret"`
}

type Authentication struct {
	ServicePrincipal ServicePrincipal `toml:"service_principal"`
}

type StorageConfig struct {
	Enabled            bool   `toml:"enabled"`
	StorageAccountName string `toml:"storage_account_name"`
	ContainerName      string `toml:"container_name"`
	SASToken           string `toml:"sas_token"`
}

type Config struct {
	Authentication Authentication `toml:"authentication"`
	Storage        StorageConfig  `toml:"storage"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if cfg.Authentication.ServicePrincipal.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	if cfg.Authentication.ServicePrincipal.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if cfg.Authentication.ServicePrincipal.ClientSecret == "" {
		return nil, fmt.Errorf("client_secret is required")
	}

	// Validate storage configuration if enabled
	if cfg.Storage.Enabled {
		if cfg.Storage.StorageAccountName == "" {
			return nil, fmt.Errorf("storage_account_name is required when storage is enabled")
		}
		if cfg.Storage.ContainerName == "" {
			return nil, fmt.Errorf("container_name is required when storage is enabled")
		}
		if cfg.Storage.SASToken == "" {
			return nil, fmt.Errorf("sas_token is required when storage is enabled")
		}
		if !strings.HasPrefix(cfg.Storage.SASToken, "?") {
			return nil, fmt.Errorf("sas_token must start with '?'")
		}
	}

	return &cfg, nil
}
