package main

import (
	"bufio"
	"context"
	"fmt"
	"github.com/sayuthisobri/headless-sso/process"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"regexp"
	"time"
)

func main() {

	dto := &loginDto{}

	_ = (&cli.App{
		EnableBashCompletion:   true,
		UseShortOptionHandling: true,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "debug",
				Aliases:     []string{"d"},
				Usage:       "enable debug",
				Value:       false,
				Destination: &dto.isDebug,
			},
			&cli.BoolFlag{
				Name:        "trace",
				Aliases:     []string{"t"},
				Usage:       "enable trace",
				Value:       false,
				Destination: &dto.isTrace,
			},
			&cli.StringFlag{
				Name:        "url",
				Aliases:     []string{"u"},
				Usage:       "url",
				Destination: &dto.url,
			},
			&cli.IntFlag{
				Name:        "timeout",
				Usage:       "Input timeout in seconds",
				Value:       60,
				Destination: &dto.timeout,
			},
		},
		Commands: []*cli.Command{
			{
				Name:   "login",
				Action: loginFn(dto),
				Usage:  "Login aws sso",
			},
		},
		DefaultCommand: "login",
	}).Run(os.Args)
}

func loginFn(dto *loginDto) func(ctx *cli.Context) error {
	return func(ctx *cli.Context) error {
		var url string
		if ctx.NArg() > 0 {
			r, _ := regexp.Compile("^https.*")
			arg0 := ctx.Args().Get(0)
			if r.MatchString(arg0) {
				url = arg0
			}
		}
		if len(dto.url) != 0 {
			url = dto.url
		}
		if len(url) == 0 {
			url = readStdIn(dto.timeout)
		}
		if len(url) == 0 {
			log.Fatalf("No valid url found")
		}
		log.Printf("Proceed with url: %s", url)
		process.SsoLogin(url, dto.isTrace, dto.isDebug)
		return nil
	}
}

func readStdIn(timeout int) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	result := make(chan string)

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Printf("Wait for valid url\n")
		for scanner.Scan() {
			t := scanner.Text()
			r, _ := regexp.Compile("^https.*user_code=([A-Z]{4}-?){2}")
			r2, _ := regexp.Compile("^https://.+\\.awsapps\\.com/start")

			if r.MatchString(t) || r2.MatchString(t) {
				result <- t
			}
		}
	}()
	url := ""
	select {
	case r := <-result:
		url = r
	case <-ctx.Done():
		fmt.Println("timeout")
	}
	return url
}

type loginDto struct {
	url     string
	isTrace bool
	isDebug bool
	timeout int
}
