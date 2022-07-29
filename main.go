package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/sayuthisobri/headless-sso/aws"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"regexp"
	"time"
)

func main() {

	dto := &reqDto{}

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
			{
				Name:   "token",
				Action: tokenFn(dto),
				Usage:  "Retrieve aws developer token",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "instance",
						Aliases:     []string{"i"},
						Value:       "0",
						Destination: &dto.instance,
					},
					&cli.StringFlag{
						Name:        "profile",
						Aliases:     []string{"p"},
						Value:       "1",
						Destination: &dto.profile,
					},
				},
			},
		},
		DefaultCommand: "login",
	}).Run(os.Args)
}

func tokenFn(dto *reqDto) cli.ActionFunc {
	return func(c *cli.Context) error {
		sso := aws.SSOHandler{IsTraceEnabled: dto.isTrace, IsDebugEnabled: dto.isDebug}
		err := sso.GetToken(dto.instance, dto.profile)
		handleError(err)
		return err
	}
}

func loginFn(dto *reqDto) func(ctx *cli.Context) error {
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
		log.Printf("Proceed with url: [%s]", url)
		sso := aws.SSOHandler{IsTraceEnabled: dto.isTrace, IsDebugEnabled: dto.isDebug}
		err := sso.Login(url)
		handleError(err)
		return err
	}
}

func handleError(err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		log.Panic("Timeout")
	} else if err != nil {
		log.Panic(err)
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

type reqDto struct {
	url      string
	isTrace  bool
	isDebug  bool
	timeout  int
	profile  string
	instance string
}
