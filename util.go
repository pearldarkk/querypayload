package main

import (
	"errors"
	"fmt"
	urllib "net/url"
	"os"
	"strconv"

	"github.com/logrusorgru/aurora/v3"
)

func isURL(s string) bool {
	_, e := urllib.ParseRequestURI(s)
	if e != nil {
		return false
	}

	u, e := urllib.Parse(s)
	if e != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

func showBanner() {
	fmt.Fprintf(os.Stderr, "%s\n", aurora.Cyan(banner))
}

func (opt *options) getSearchResult() ([]string, error) {
	queryEsc := urllib.QueryEscape(opt.Query)
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
		return nil, errors.New("unknown engine " + opt.Engine)
	}

iterPage:
	for p := 1; p <= opt.Page; p++ {
		page := strconv.Itoa(p)
		page += "0"
		scrape, err := opt.get(baseURL + "?" + params + page)
		if err != nil {
			return nil, err
		}
		result := parser(scrape, regexes)
		for i := range result {
			url, err := urllib.QueryUnescape(result[i][1])
			if err != nil {
				return nil, err
			}
			if !isURL(url) {
				break iterPage
			}
			res = append(res, url)
		}
	}
	return res, nil
}
