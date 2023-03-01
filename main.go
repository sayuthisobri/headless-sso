package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/sayuthisobri/headless-sso/aws"
	"github.com/urfave/cli/v2"
	"io"
	"log"
	"os"
	"os/exec"
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
			&cli.StringFlag{
				Name:        "profile",
				Aliases:     []string{"p"},
				Destination: &dto.profile,
			},
		},
		Commands: []*cli.Command{
			{
				Name:   "login",
				Action: loginFn(dto),
				Usage:  "HandleUrl aws sso",
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
			if len(dto.profile) != 0 {
				cmd := exec.Command("aws", "sso", "login", "--profile", dto.profile, "--no-browser")
				result := make(chan string)
				// pipe the commands output to the applications
				// standard output
				stdout, err := cmd.StdoutPipe()
				if nil != err {
					log.Fatalf("Error obtaining stdout: %s", err.Error())
				}
				reader := bufio.NewReader(stdout)
				go func() {
					result <- scanUrl(dto.timeout, reader)
				}()

				// Run still runs the command and waits for completion
				// but the output is instantly piped to Stdout
				if err := cmd.Start(); err != nil {
					fmt.Println("could not run command: ", err)
				}
				select {
				case url = <-result:
					if len(url) == 0 {
						_ = cmd.Process.Kill()
					}
				}
			} else {
				url = scanUrl(dto.timeout, os.Stdin)
			}
		}
		if len(url) == 0 {
			log.Fatalf("No valid url found")
		}
		log.Printf("Proceed with url: [%s]", url)
		sso := aws.SSOHandler{IsTraceEnabled: dto.isTrace, IsDebugEnabled: dto.isDebug}
		err := sso.HandleUrl(url)
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

func scanUrl(timeout int, src io.Reader) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	result := make(chan string)

	go func() {
		scanner := bufio.NewScanner(src)
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
		fmt.Println("Timeout while scan for valid url")
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
