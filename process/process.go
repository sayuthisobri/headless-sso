package process

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-rod/rod/lib/launcher"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/git-lfs/go-netrc/netrc"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
)

const MfaTimeout = 30
const CacheName = ".headless-sso"

// SsoLogin login with U2f MFA
func SsoLogin(url string, trace bool, debug bool) {
	browser := rod.New().
		Trace(trace)

	if debug {
		l := launcher.New().
			Headless(false).
			Devtools(true)

		defer l.Cleanup() // remove launcher.FlagUserDataDir

		debugUrl := l.MustLaunch()

		browser.ControlURL(debugUrl).
			SlowMotion(1 * time.Second)
	}
	browser.MustConnect()

	loadCookies(*browser)

	defer browser.MustClose()

	err := rod.Try(func() {

		page := browser.MustPage(url)
		unauthorized := true
		attempts := 0

		allowHandler := func(e *rod.Element) {
			e.MustClick()
			log.Println("Allowing..")
			attempts = 0
		}

		successHandler := func(e *rod.Element) {
			log.Println("Success")
			unauthorized = false
		}

		responseMsgCheckHandler := func(e *rod.Element) {
			if e.MustText() == "Request approved" {
				unauthorized = false
			}
			log.Println(e.MustText())
		}

		signInHandler := func(e *rod.Element) {
			signIn(*page)
		}

		logErrorHandler := func(e *rod.Element) {
			title := e.MustElement(".alert-header").MustText()
			text := e.MustElement(".alert-content").MustText()
			log.Fatalf("[ERROR] %s - %s\n", title, text)
		}

		// sign-in
		page.
			Timeout(10*time.Second).MustWaitLoad().
			Race().
			Element("span.user-display-name").MustHandle(successHandler).
			ElementR("button", "Allow").MustHandle(allowHandler).
			Element("#awsui-input-0").MustHandle(signInHandler).
			Element(".awsui-alert-type-error").MustHandle(logErrorHandler).
			MustDo().
			CancelTimeout()

		for unauthorized {
			page.Timeout(MfaTimeout*time.Second).Race().
				Element("span.user-display-name").MustHandle(successHandler).
				ElementR("button", "Allow").MustHandle(allowHandler).
				Element(".awsui-util-mb-s").MustHandle(responseMsgCheckHandler).MustDo().
				CancelTimeout()

			if unauthorized && attempts > 1 {
				page.MustWaitLoad().MustScreenshot("")
			}
			time.Sleep(500 * time.Millisecond)
			attempts++
		}

		saveCookies(*browser)
	})

	if errors.Is(err, context.DeadlineExceeded) {
		log.Panic("Timeout")
	} else if err != nil {
		log.Panic(err)
	}
}

// executes aws sso signin step
func signIn(page rod.Page) {
	usr, _ := user.Current()

	f, _ := netrc.ParseFile(filepath.Join(usr.HomeDir, ".netrc"))
	username := f.FindMachine("headless-sso", "").Login
	passphrase := f.FindMachine("headless-sso", "").Password
	totpKey := f.FindMachine("headless-sso", "").Account

	log.Println("Authenticating..")
	page.MustElement("#awsui-input-0").MustInput(username).MustPress(input.Enter)
	page.MustElement("#awsui-input-1").MustInput(passphrase).MustPress(input.Enter)

	mfa(page, totpKey)
}

func mfa(page rod.Page, key string) {
	page.MustWaitLoad().Race().ElementR("#awsui-input-0-label", "MFA code").MustHandle(func(e *rod.Element) {
		log.Println("Handle MFA code")
		token := GetTOTPToken(key)
		mfaInput := page.MustElement("#awsui-input-0").MustInput(token)
		//log.Printf("Input token: %s\n", token)
		mfaInput.MustPress(input.Enter)
		time.Sleep(1 * time.Second)

	}).Element("span.user-display-name").MustHandle(func(e *rod.Element) {
		log.Println("Success")
	}).MustDo()
}

// load cookies
func loadCookies(browser rod.Browser) {
	dirname, err := os.UserHomeDir()
	if err != nil {
		log.Panic(err)
	}

	data, _ := os.ReadFile(dirname + "/.headless-sso")
	sEnc, _ := b64.StdEncoding.DecodeString(string(data))
	var cookie *proto.NetworkCookie
	err = json.Unmarshal(sEnc, &cookie)
	if err != nil {
		return
	}

	if cookie != nil {
		browser.MustSetCookies(cookie)
	}
}

// save authn cookie
func saveCookies(browser rod.Browser) {
	dirname, err := os.UserHomeDir()
	if err != nil {
		log.Panic(err)
	}

	cookies := browser.MustGetCookies()

	for _, cookie := range cookies {
		if cookie.Name == "x-amz-sso_authn" {
			data, _ := json.Marshal(cookie)

			sEnc := b64.StdEncoding.EncodeToString(data)
			err = os.WriteFile(fmt.Sprintf("%s/%s", dirname, CacheName), []byte(sEnc), 0644)

			if err != nil {
				log.Panic(err)
			}
			break
		}
	}
}
