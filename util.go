package main

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/logrusorgru/aurora/v3"
	log "github.com/projectdiscovery/gologger"
)

func isURL(s string) bool {
	_, e := url.ParseRequestURI(s)
	if e != nil {
		return false
	}

	u, e := url.Parse(s)
	if e != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

func parseAccess(config Config, uriMap map[string]int) error {
	uriPattern := `(?:GET|POST|CONNECT|TUNNEL|HEAD|PUT|DELETE|OPTIONS|TRACE|PATCH)\s([^\;\s]+)`
	statusPattern := `[\s\t](\d+)[\s\t]\d+[\s\t]`
	timePattern := config.TimePattern
	if timePattern == "" {
		timePattern = `(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`
	}
	uriRegex, err := regexp.Compile(uriPattern)
	statusRegex, err := regexp.Compile(statusPattern)
	timeRegex, err := regexp.Compile(timePattern)

	if config.LogPattern == "" {
		config.LogPattern = "*.log"
	}
	files, err := filepath.Glob(config.LogPattern)
	if err != nil {
		return fmt.Errorf("Error read file: %v", err)
	}

	var fromTime, toTime time.Time
	if config.FromTime != "" {
		fromTimeParsed, err := time.Parse("2006-01-02 15:04:05", config.FromTime)
		if err != nil {
			return err
		}
		fromTime = fromTimeParsed
	}
	if config.ToTime != "" {
		toTimeParsed, err := time.Parse("2006-01-02 15:04:05", config.ToTime)
		if err != nil {
			return err
		}
		toTime = toTimeParsed
	}

	for _, file := range files {
		file, err := os.Open(file)
		if err != nil {
			return err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			line := scanner.Text()

			if config.FromTime != "" || config.ToTime != "" {
				timeMatches := timeRegex.FindStringSubmatch(line)
				if len(timeMatches) > 1 {
					logTime, err := time.Parse("2006-01-02 15:04:05", timeMatches[1])
					if err != nil {
						fmt.Errorf("Failed to parse time: %v\n", err)
						continue
					}

					if config.FromTime != "" && logTime.Before(fromTime) {
						continue
					}

					if config.ToTime != "" && logTime.After(toTime) {
						continue
					}
				}
			}

			uriMatches := uriRegex.FindStringSubmatch(line)
			statusMatches := statusRegex.FindStringSubmatch(line)

			if len(uriMatches) > 1 && len(statusMatches) > 1 {
				encodedURI := uriMatches[1]
				statusCode := statusMatches[1]

				if config.FilterStatus != "" && "200" != statusCode {
					continue
				}

				decodedURI, err := url.QueryUnescape(encodedURI)
				if err != nil {
					fmt.Errorf("Failed to decode URI %s: %v\n", encodedURI, err)
					continue
				}

				uriMap[decodedURI]++
			}
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	}

	return nil
}

func isError(e error) {
	if e != nil {
		log.Fatal().Msgf("%s\n", e)
	}
}

func showBanner() {
	fmt.Fprintf(os.Stderr, "%s\n", aurora.Cyan(banner))
}

func (opt *options) getSearchResult() ([]string, error) {
	queryEsc := url.QueryEscape(opt.Query)
	var regexes, baseURL, params string
	var res []string

	switch opt.Engine {
	case "google":
		regexes = `"><a href="\/url\?q=(.*?)&amp;sa=U&amp;`
		baseURL = "https://www.google.com/search"
		params = ("q=" + queryEsc + "&gws_rd=cr,ssl&client=ubuntu&ie=UTF-8&start=")
	case "shodan":
		regexes = `\"><a href=\"/host/(.*?)\">`
		baseURL = "https://www.shodan.io/search"
		params = ("query=" + queryEsc + "&page=")
	default:
		return nil, errors.New("engine not found! Please choose one available")
	}

iterPage:
	for p := 1; p <= opt.Page; p++ {
		page := strconv.Itoa(p)

		scrape := opt.get(baseURL + "?" + params + page)
		result := parser(scrape, regexes)
		for i := range result {
			url, err := url.QueryUnescape(result[i][1])
			if err != nil {
				return nil, fmt.Errorf("when querying '%s' on page %d", queryEsc, p)
			}

			if !isURL(url) {
				break iterPage
			}

			res = append(res, url)
		}
	}

	return res, nil
}
