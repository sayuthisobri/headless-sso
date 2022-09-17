package config

import (
  "fmt"
  "github.com/git-lfs/go-netrc/netrc"
  "gopkg.in/ini.v1"
  "log"
  "os"
  "os/user"
  "path/filepath"
  "strings"
)

const ProcessTimeout = 60
const CacheName = ".headless-sso"

func GetConfigs() []AwsConfig {
	cfg, err := ini.Load(filepath.Join(GetHomeDir(), ".aws", "config"))
	if err != nil {
		fmt.Printf("Fail to read file: %v", err)
		os.Exit(1)
	}

	configs := make([]AwsConfig, len(cfg.Sections()))
	skip := 0
	for i, section := range cfg.Sections() {
		ssoStartUrl := section.Key("sso_start_url").Value()
		if len(ssoStartUrl) > 0 {
			configs[i-skip] = AwsConfig{
				Name:         strings.Replace(section.Name(), "profile ", "", 1),
				SSOStartUrl:  ssoStartUrl,
				SsoRegion:    section.Key("sso_region").Value(),
				SsoAccountId: section.Key("sso_account_id").Value(),
				SsoRoleName:  section.Key("sso_role_name").Value(),
				Region:       section.Key("region").Value(),
				Output:       section.Key("output").Value(),
			}
		} else {
			skip++
		}
	}
	return configs[:len(configs)-skip]
}

func GetDefaultConfig() *AwsConfig {
	configs := GetConfigs()
	if len(configs) == 0 {
		return nil
	}
	return &configs[0]
}

func GetHomeDir() string {
	dirname, err := os.UserHomeDir()
	if err != nil {
		log.Panic(err)
	}
	return dirname
}

func GetCachePath() string {
	return filepath.Join(GetHomeDir(), CacheName)
}

func GetAuth() SSOAuth {
  usr, _ := user.Current()

  f, _ := netrc.ParseFile(filepath.Join(usr.HomeDir, ".netrc"))
  username := f.FindMachine("headless-sso", "").Login
  passphrase := f.FindMachine("headless-sso", "").Password
  totpKey := f.FindMachine("headless-sso", "").Account
  return SSOAuth{
    Login: username,
    Pass:  passphrase,
    TOTP:  totpKey,
  }
}

type AwsConfig struct {
  Name         string
  SSOStartUrl  string
  SsoRegion    string
  SsoAccountId string
  SsoRoleName  string
  Region       string
  Output       string
}

type SSOAuth struct {
  Login, Pass, TOTP string
}
