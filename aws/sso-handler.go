package aws

import (
	b64 "encoding/base64"
	"encoding/json"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/sayuthisobri/headless-sso/config"
	"golang.design/x/clipboard"
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
}

func (aws *SSOHandler) Login(url string) (*rod.Browser, error) {
	browser, _launcher := aws.GetBrowser()
	defer aws.Cleanup(browser, _launcher)

	return browser, rod.Try(func() {
		aws.doLogin(browser, url)
	})
}

func (aws *SSOHandler) doLogin(browser *rod.Browser, url string) *rod.Page {
	page := browser.MustPage(url)

	successHandler := func(e *rod.Element) {
		log.Println("Login Success")
		aws.authorized = true
	}
	allowHandler := func(e *rod.Element) {
		e.MustClick()
		log.Println("Allowing..")
		aws.attempts = 0
	}
	statusCheckHandler := func(e *rod.Element) {
		if e.MustText() == "Request approved" {
			aws.authorized = true
		}
		log.Println(e.MustText())
	}

	page.
		Timeout(10*time.Second).MustWaitLoad().
		Race().
		Element("span.user-display-name").MustHandle(successHandler).
		ElementR("button", "Allow").MustHandle(allowHandler).
		Element("#awsui-input-0").MustHandle(func(e *rod.Element) {
		fillUpAuth(*e.Page())
	}).
		Element(".awsui-alert-type-error").MustHandle(func(e *rod.Element) {
		title := e.MustElement(".alert-header").MustText()
		text := e.MustElement(".alert-content").MustText()
		log.Fatalf("[ERROR] %s - %s\n", title, text)
	}).
		MustDo().
		CancelTimeout()

	for !aws.authorized {
		page.Timeout(config.MfaTimeout*time.Second).Race().
			Element("span.user-display-name").MustHandle(successHandler).
			ElementR("button", "Allow").MustHandle(allowHandler).
			Element(".awsui-util-mb-s").MustHandle(statusCheckHandler).MustDo().
			CancelTimeout()

		if !aws.authorized && aws.attempts > 1 {
			page.MustWaitLoad().MustScreenshot("")
		}
		time.Sleep(500 * time.Millisecond)
		aws.attempts++
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
	browser.MustConnect()

	loadCookies(*browser)

	return browser, _launcher
}

func (aws *SSOHandler) GetToken(arg string, profileArg string) error {
	browser, _launcher := aws.GetBrowser()
	defer aws.Cleanup(browser, _launcher)

	return rod.Try(func() {
		page := aws.doLogin(browser, config.GetDefaultConfig().SSOStartUrl).
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
			copyBtn := matchedProfile.MustElement("#temp-credentials-button").MustClick().Page().
				MustElement("creds-modal").MustWaitStable().
				MustElement("#hover-copy-env")
			copyBtn.MustClick()

			if data := clipboard.Read(clipboard.FmtText); len(data) > 0 {
				f, err := os.Create(filepath.Join(config.GetHomeDir(), ".aws", "credentials"))

				if err != nil {
					log.Fatal(err)
				}

				defer f.Close()

				_, err2 := f.Write(data)

				if err2 != nil {
					log.Fatal(err2)
				}
			}
		}
	})
}

func index(slice rod.Elements, item *rod.Element) int {
	for i := range slice {
		if slice[i] == item {
			return i
		}
	}
	return -1
}

func (aws *SSOHandler) Cleanup(browser *rod.Browser, l *launcher.Launcher) {
	if browser != nil {
		browser.MustClose()
	}
	if l != nil {
		l.Cleanup()
	}
}

func fillUpAuth(page rod.Page) {
	username, passphrase, totpKey := config.GetAuth()

	log.Println("Authenticating..")
	page.MustElement("#awsui-input-0").MustInput(username).MustPress(input.Enter)
	page.MustElement("#awsui-input-1").MustInput(passphrase).MustPress(input.Enter)

	handleMfa(page, totpKey)
}

func handleMfa(page rod.Page, key string) {
	page.MustWaitLoad().Race().ElementR("#awsui-input-0-label", "MFA code").MustHandle(func(e *rod.Element) {
		log.Println("Handle MFA code")
		token := GetTOTPToken(key)
		mfaInput := page.MustElement("#awsui-input-0").MustInput(token)
		mfaInput.MustPress(input.Enter)
		time.Sleep(1 * time.Second)
	}).Element("span.user-display-name").MustHandle(func(e *rod.Element) {
	}).MustDo()
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
