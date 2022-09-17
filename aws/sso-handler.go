package aws

import (
	b64 "encoding/base64"
	"encoding/json"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/sayuthisobri/headless-sso/config"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
)

type SSOHandler struct {
  IsTraceEnabled bool
  IsDebugEnabled bool
  authorized     bool
  attempts       int
  auth           config.SSOAuth
}

func (aws *SSOHandler) HandleUrl(url string) error {
  browser, _launcher := aws.GetBrowser()
  defer aws.Cleanup(browser, _launcher)

  return rod.Try(func() {
    aws.handleUrl(browser, url)
  })
}

func (aws *SSOHandler) handleUrl(browser *rod.Browser, url string) *rod.Page {
  page := browser.MustPage(url).
    Timeout(config.ProcessTimeout * time.Second)

  successHandler := func(e *rod.Element) {
    log.Println("Login Success")
    aws.authorized = true
  }
  allowHandler := func(e *rod.Element) {
    e.MustWaitStable().MustClick()
    log.Println("Allowing..")
    aws.attempts = 0
  }
  statusCheckHandler := func(e *rod.Element) {
    if e.MustText() == "Request approved" {
      aws.authorized = true
    }
    log.Println(e.MustText())
  }
  loginHandler := func(e *rod.Element) {
    aws.auth = config.GetAuth()

    log.Println("Authenticating..")
    page.MustElement("#awsui-input-0").MustInput(aws.auth.Login).MustType(input.Enter)
    page.MustElement("#awsui-input-1").MustInput(aws.auth.Pass).MustType(input.Enter)
  }
  mfaHandler := func(e *rod.Element) {
    log.Println("Handle MFA code")
    token := GetTOTPToken(aws.auth.TOTP)
    mfaInput := page.MustElement("#awsui-input-0").MustInput(token)
    mfaInput.MustType(input.Enter)
    time.Sleep(1 * time.Second)
  }

  page.MustWaitLoad()

  for !aws.authorized {
    page.Race().
      Element("span.user-display-name").MustHandle(successHandler).
      Element(".awsui-util-mb-s").MustHandle(statusCheckHandler).
      ElementR("button", "Allow").MustHandle(allowHandler).
      ElementR("#awsui-input-0-label", "Username").MustHandle(loginHandler).
      ElementR("#awsui-input-0-label", "MFA code").MustHandle(mfaHandler).
      Element(".awsui-alert-type-error").MustHandle(func(e *rod.Element) {
      title := e.MustElement(".alert-header").MustText()
      text := e.MustElement(".alert-content").MustText()
      log.Fatalf("[ERROR] %s - %s\n", title, text)
    }).MustDo()

    //if !aws.authorized {
    //  log.Println("Not authorized. retry in 2s")
    //}
    time.Sleep(200 * time.Millisecond)
  }

  saveCookies(*browser)
  return page
}

func (aws *SSOHandler) GetBrowser() (*rod.Browser, *launcher.Launcher) {
	var _launcher *launcher.Launcher
	browser := rod.New().
		Trace(aws.IsTraceEnabled)

	if aws.IsDebugEnabled {
		_launcher = launcher.New()
		debugUrl := _launcher.
			Headless(false).
			Devtools(true).
			MustLaunch()
		browser.ControlURL(debugUrl)
	}
	browser.MustConnect().SlowMotion(200 * time.Millisecond)

	loadCookies(*browser)

	return browser, _launcher
}

func (aws *SSOHandler) GetToken(arg string, profileArg string) error {
	browser, _launcher := aws.GetBrowser()
	defer aws.Cleanup(browser, _launcher)

	return rod.Try(func() {
    page := aws.handleUrl(browser, config.GetDefaultConfig().SSOStartUrl).CancelTimeout().
      MustElement("portal-application").MustClick().
      Page()
    instances := page.MustElements("portal-instance")
    instancesName := make([]string, len(instances))
    var matchedInstance *rod.Element
    for i, instance := range instances {
      instancesName[i] = instance.MustElement("div.name").MustText()
      if strconv.Itoa(i) == arg || instancesName[i] == arg {
        matchedInstance = instance
      }
    }
    if matchedInstance == nil {
      log.Printf("No instance found for %s\n", arg)
      log.Printf("Available instances: %s\n", strings.Join(instancesName, ", "))
    } else {
      log.Printf("Selected instance: %s\n", instancesName[index(instances, matchedInstance)])
      profiles := matchedInstance.MustClick().
        MustWaitStable().
        MustElements("portal-profile")
      profilesName := make([]string, len(profiles))
      var matchedProfile *rod.Element
      for i, profile := range profiles {
        profilesName[i] = profile.MustElement("span.profile-name").MustText()
        if strconv.Itoa(i) == profileArg || profilesName[i] == profileArg {
          matchedProfile = profile
        }
      }
      if matchedProfile == nil {
        if len(profiles) == 0 {
          log.Fatalf("No profile available for this instance\n")
        } else {
          matchedProfile = profiles.First()
        }
      }
      log.Printf("Selected profile: %s\n", profilesName[index(profiles, matchedProfile)])
      matchedProfile.MustElement("#temp-credentials-button").MustClick()
      lines := page.Timeout(config.ProcessTimeout * time.Second).
        MustElement("creds-modal").MustWaitStable().
        MustElement("#cli-cred-file-code").MustElements(".code-line")
      data := ""
      for _, line := range lines {
        data += line.MustText() + "\n"
      }
      if len(data) > 0 {
        credPath := filepath.Join(config.GetHomeDir(), ".aws", "credentials")
        f, err := os.Create(credPath)

        if err != nil {
          log.Fatal(err)
        }

        defer f.Close()

        _, err = f.WriteString(data)
        if err != nil {
          log.Fatal(err)
        }

        log.Printf("Successfully update credentials file: %s", credPath)
      }
		}
	})
}

func (aws *SSOHandler) Cleanup(browser *rod.Browser, l *launcher.Launcher) {
	if browser != nil {
		browser.MustClose()
	}
	if l != nil {
		l.Cleanup()
	}
}

// load cookies
func loadCookies(browser rod.Browser) {
	data, _ := os.ReadFile(config.GetCachePath())
	sEnc, _ := b64.StdEncoding.DecodeString(string(data))
	var cookie *proto.NetworkCookie
	err := json.Unmarshal(sEnc, &cookie)
	if err != nil {
		return
	}

	if cookie != nil {
		browser.MustSetCookies(cookie)
	}
}

// save authn cookie
func saveCookies(browser rod.Browser) {
	cookies := browser.MustGetCookies()

	for _, cookie := range cookies {
		if cookie.Name == "x-amz-sso_authn" {
			data, _ := json.Marshal(cookie)

			sEnc := b64.StdEncoding.EncodeToString(data)
			err := os.WriteFile(config.GetCachePath(), []byte(sEnc), 0644)

			if err != nil {
				log.Panic(err)
			}
			break
		}
	}
}

func index(slice rod.Elements, item *rod.Element) int {
	for i := range slice {
		if slice[i] == item {
			return i
		}
	}
	return -1
}
