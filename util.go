package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"

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

func isError(e error) {
	if e != nil {
		log.Info().Msgf("%s\n", e)
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
