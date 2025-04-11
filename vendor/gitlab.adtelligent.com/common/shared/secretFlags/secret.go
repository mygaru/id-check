package secretFlags

import (
	"flag"
	"fmt"
	"github.com/vharitonsky/iniflags"
	"gitlab.adtelligent.com/common/shared/log"
	"gitlab.adtelligent.com/common/shared/util"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type SecretManager interface {
	// InitManager
	// If "SECRET_URI" is not set, it would check for the environment and flag values.
	// Otherwise, the appropriate adapter will be connected.
	InitManager()
	GetCredentials() map[string]interface{}
}

var secretURI string

func Init() {
	iniflags.Parse()
	util.LogAllFlags()

	vaultEnabled := os.Getenv("vaultEnabled")

	isVaultEnabled := false
	if vaultEnabled != "" {
		parsed, err := strconv.ParseBool(vaultEnabled)
		if err != nil {
			log.Fatalf("Invalid value for vaultEnabled: %s\n", vaultEnabled)
			return
		} else {
			isVaultEnabled = parsed
		}
	}

	if isVaultEnabled {
		if secretURI != "" {
			var err error
			secretManager, err := newSecretManager(secretURI)
			if err != nil {
				log.Fatalf("Error initializing secret manager: %s", err)
				return
			}

			secretManager.InitManager()

			overrideFlags(secretManager.GetCredentials())
		} else {
			log.Fatalf("Vault secret URI is not set")
			return
		}
	} else {
		log.Infof("Vault is not set. Proceeding with environment and flag values...")
		overrideFlags(getEnvVariables())
	}
}

func newSecretManager(secretURI string) (SecretManager, error) {
	uri, err := url.Parse(secretURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse secret URI: %v", err)
	}

	switch uri.Scheme {
	case "vault":
		return NewAdapter(uri)
	default:
		return nil, fmt.Errorf("unsupported secret manager: %s", uri.Scheme)
	}
}

func getEnvVariables() map[string]interface{} {
	envVars := make(map[string]interface{})
	for _, e := range os.Environ() {
		pair := parseEnvVariable(e)
		envVars[pair[0]] = pair[1]
	}

	return envVars
}

func parseEnvVariable(env string) [2]string {
	var pair [2]string
	if idx := strings.Index(env, "="); idx != -1 {
		pair[0] = strings.TrimSpace(env[:idx])
		pair[1] = strings.TrimSpace(env[idx+1:])
	}

	return pair
}

func overrideFlags(credentials map[string]interface{}) {
	flag.VisitAll(func(f *flag.Flag) {
		var err error
		if value, ok := credentials[f.Name]; ok {
			switch v := value.(type) {
			case string:
				err = flag.Set(f.Name, v)
			case float64, float32:
				err = flag.Set(f.Name, fmt.Sprintf("%f", v))
			case int, uint64, uint32:
				err = flag.Set(f.Name, fmt.Sprintf("%d", v))
			case bool:
				err = flag.Set(f.Name, fmt.Sprintf("%v", v))
			default:
				err = fmt.Errorf("unsupported type %T", value)
			}
			if err != nil {
				log.Errorf("Failed to set flag %s: %v", f.Name, err)
			}
		}
	})
}
