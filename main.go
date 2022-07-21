package main

import (
	"bufio"
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"github.com/fatih/color"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"time"

	"github.com/git-lfs/go-netrc/netrc"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
)

// Time before MFA step times out
const MFA_TIMEOUT = 30

func main() {

	// fetch url from stdin
	url := getURL()
	color.Cyan(url)

	// login headlessly
	ssoLogin(url)
	time.Sleep(1 * time.Second)
}

// returns sso url from stdin.
func getURL() string {
	scanner := bufio.NewScanner(os.Stdin)
	url := ""
	for url == "" {
		scanner.Scan()
		t := scanner.Text()
		r, _ := regexp.Compile("^https.*user_code=([A-Z]{4}-?){2}")

		if r.MatchString(t) {
			url = t
		}
	}

	return url
}

// login with U2f MFA
func ssoLogin(url string) {

	browser := rod.New().
		MustConnect().
		Trace(false)

	loadCookies(*browser)

	defer browser.MustClose()

	err := rod.Try(func() {

		page := browser.MustPage(url)
		//page.MustElement("div").MustWaitLoad()
		// authorize
		//page.MustWaitLoad().MustScreenshot("a.png")

		// sign-in
		page.MustWaitLoad().Race().Element("span.user-display-name").MustHandle(func(e *rod.Element) {
		}).ElementR("button", "Allow").MustHandle(func(e *rod.Element) {
		}).Element("#awsui-input-0").MustHandle(func(e *rod.Element) {
			signIn(*page)
		}).MustDo()

		// allow request
		unauthorized := true
		for unauthorized {
			page.Timeout(MFA_TIMEOUT*time.Second).Race().Element("span.user-display-name").MustHandle(func(e *rod.Element) {
				log.Println("Success")
				unauthorized = false
			}).ElementR("button", "Allow").MustHandle(func(e *rod.Element) {
				e.MustClick()
				log.Println("Allowing..")
			}).Element(".awsui-util-mb-s").MustHandle(func(e *rod.Element) {
				if e.MustText() == "Request approved" {
					unauthorized = false
				}
				log.Println(e.MustText())
			}).MustDo()
			time.Sleep(500 * time.Millisecond)
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
	page.Race().ElementR("#awsui-input-0-label", "MFA code").MustHandle(func(e *rod.Element) {
		log.Println("Handle MFA code")
		page.MustElement("#awsui-input-0").MustInput(GetTOTPToken(key)).MustPress(input.Enter)
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
	json.Unmarshal(sEnc, &cookie)

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

	cookies := (browser.MustGetCookies())

	for _, cookie := range cookies {
		if cookie.Name == "x-amz-sso_authn" {
			data, _ := json.Marshal(cookie)

			sEnc := b64.StdEncoding.EncodeToString([]byte(data))
			err = os.WriteFile(dirname+"/.headless-sso", []byte(sEnc), 0644)

			if err != nil {
				log.Panic(err)
			}
			break
		}
	}
}
