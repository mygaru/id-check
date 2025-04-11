package secretFlags

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"gitlab.adtelligent.com/common/shared/log"
	"net/url"
	"time"
)

type Manager struct {
	client          *vault.Client
	vaultAddress    string
	secretPath      string
	roleID          string
	secretID        string
	token           string
	tokenExpiration time.Duration
	renewalInterval time.Duration
}

var data = make(map[string]interface{})

func InitManager(vm Manager) {
	ctx := context.Background()

	vm.auth(ctx)

	err := vm.readSecret(ctx, vm.secretPath)
	if err != nil {
		log.Fatalf("Failed to read secret: %v", err)
	}

	go func() {
		ste := time.Duration(0.8 * float64(vm.tokenExpiration))
		sri := time.Duration(0.8 * float64(vm.renewalInterval))

		time.Sleep(ste)

		_, err = vm.renewToken(ctx, vm.renewalInterval)
		if err != nil {
			log.Errorf("Token renewal failed: %v", err)
		}

		ticker := time.NewTicker(sri)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				_, err = vm.renewToken(ctx, vm.renewalInterval)
				if err != nil {
					log.Errorf("Token renewal failed: %v", err)
				}
			}
		}
	}()
}

func NewManager(vaultAddress, secretPath, roleID, secretID string, tokenExpiration, renewalInterval time.Duration) (*Manager, error) {
	client, err := vault.New(
		vault.WithAddress(fmt.Sprintf("https://%s", vaultAddress)),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Errorf("Failed to create Vault client: %v", err)
		return nil, err
	}

	return &Manager{
		client:          client,
		secretPath:      secretPath,
		roleID:          roleID,
		secretID:        secretID,
		tokenExpiration: tokenExpiration,
		renewalInterval: renewalInterval,
	}, nil
}

func (vm *Manager) auth(ctx context.Context) {
	resp, err := vm.client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{
		RoleId:   vm.roleID,
		SecretId: vm.secretID,
	})
	if err != nil {
		log.Fatalf("Failed to login to Vault server: %v", err)
	}

	vm.token = resp.Auth.ClientToken
	if err := vm.client.SetToken(vm.token); err != nil {
		log.Fatalf("Failed to set Vault token: %v", err)
	}
}

func (vm *Manager) readSecret(ctx context.Context, secretPath string) error {
	secretResp, err := vm.client.Read(ctx, secretPath)
	if err != nil {
		return err
	}

	dataMap, ok := secretResp.Data["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid secret response, missing 'data' field")
	}

	for key, value := range dataMap {
		data[key] = value
	}

	return nil
}

func (vm *Manager) renewToken(ctx context.Context, duration time.Duration) (int, error) {
	renewalString := (duration).Minutes()

	resp, err := vm.client.Auth.TokenRenewSelf(ctx, schema.TokenRenewSelfRequest{
		Increment: fmt.Sprintf("%dm", int(renewalString)),
	})
	if err != nil {
		return 0, err
	}

	vm.token = resp.Auth.ClientToken

	return resp.Auth.LeaseDuration, nil
}

type Adapter struct {
	vaultManager *Manager
}

func NewAdapter(uri *url.URL) (*Adapter, error) {
	vaultAddress := uri.Host
	secretPath := uri.Path
	roleID := uri.User.Username()
	secretID, _ := uri.User.Password()

	tokenExpiration, err := time.ParseDuration(uri.Query().Get("tokenExpiration"))
	if err != nil {
		tokenExpiration = 30 * time.Minute
	}

	renewalInterval, err := time.ParseDuration(uri.Query().Get("renewalInterval"))
	if err != nil {
		renewalInterval = 30 * time.Minute
	}

	manager, err := NewManager(vaultAddress, secretPath, roleID, secretID, tokenExpiration, renewalInterval)
	if err != nil {
		return nil, err
	}

	return &Adapter{vaultManager: manager}, nil
}

func (v *Adapter) InitManager() {
	InitManager(*v.vaultManager)
}

func (v *Adapter) GetCredentials() map[string]interface{} {
	return data
}
