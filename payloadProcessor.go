package main

//
//import (
//	"errors"
//	"net/http"
//	urllib "net/url"
//	"regexp"
//	"strconv"
//	"sync"
//	"time"
//
//	log "github.com/projectdiscovery/gologger"
//)
//
//func (opt *options) getSearchResult() ([]string, error) {
//	queryEsc := urllib.QueryEscape(opt.Query)
//	var regexes, baseURL, params string
//	var res []string
//
//	switch opt.Engine {
//	case "google":
//		regexes = `"><a href="\/url\?q=(.*?)&amp;sa=U&amp;`
//		baseURL = "https://www.google.com/search"
//		params = ("q=" + queryEsc + "&gws_rd=cr,ssl&client=ubuntu&ie=UTF-8&start=")
//	case "shodan":
//		regexes = `\"><a href=\"/host/(.*?)\">`
//		baseURL = "https://www.shodan.io/search"
//		params = ("query=" + queryEsc + "&page=")
//	default:
//		return nil, errors.New("unknown engine " + opt.Engine)
//	}
//
//iterPage:
//	for p := 1; p <= opt.Page; p++ {
//		page := strconv.Itoa(p)
//		page += "0"
//		scrape, err := opt.get(baseURL + "?" + params + page)
//		if err != nil {
//			return nil, err
//		}
//		result := parser(scrape, regexes)
//		for i := range result {
//			url, err := urllib.QueryUnescape(result[i][1])
//			if err != nil {
//				return nil, err
//			}
//			if !isURL(url) {
//				break iterPage
//			}
//			res = append(res, url)
//		}
//	}
//	return res, nil
//}
//
//func queryProcessor(proxies []string, queries []string, uris map[string]string, engine string, page int, headers []string) (string, error) {
//	type queryResult struct {
//		dork string
//		sus  string
//		err  error
//	}
//
//	resultChan := make(chan queryResult, len(queries))
//	proxyChan := make(chan string, len(proxies))
//
//	for _, proxy := range proxies {
//		proxyChan <- proxy
//	}
//
//	var wg sync.WaitGroup
//	for i := 0; i < 1000; i++ {
//		wg.Add(1)
//		go func(dorks <-chan string) {
//			defer wg.Done()
//			client := &http.Client{Timeout: 15 * time.Second}
//			proxyToUse := <-proxyChan
//			for dork := range dorks {
//				opts := options{
//					Query:   dork,
//					Engine:  engine,
//					Page:    page,
//					Proxy:   proxyToUse,
//					Headers: headers,
//				}
//				res, err := opts.getSearchResult()
//			}
//
//			if err != nil {
//				log.Error().Msgf("Failed to get search result with proxy %s: %v\n", proxyToUse, err)
//				resultChan <- queryResult{dork: dork, err: err}
//				proxyChan <- proxyToUse
//				return
//			}
//
//			result, err := checkPayload(res)
//			if err != nil {
//				log.Error().Msgf("Error checking payload: %v\n", err)
//				resultChan <- queryResult{dork: dork, err: err}
//				proxyChan <- proxyToUse
//				return
//			}
//
//			resultChan <- queryResult{dork: dork, sus: result}
//			proxyChan <- proxyToUse
//		}(q)
//	}
//
//	wg.Wait()
//	close(resultChan)
//
//	var finalSus string
//	for res := range resultChan {
//		if res.err != nil {
//			continue
//		}
//		uris[res.dork] = res.sus
//		if finalSus == "" {
//			finalSus = res.sus
//		}
//	}
//
//	return finalSus, nil
//}
//
//func checkPayload(urls []string) (string, error) {
//	cvePattern := `(?i)CVE-\d{4,}-\d{4,}`
//	exp := `exploit`
//	cveRegex, err := regexp.Compile(cvePattern)
//	if err != nil {
//		return "", err
//	}
//	expRegex, err := regexp.Compile(exp)
//	if err != nil {
//		return "", err
//	}
//
//	for _, url := range urls {
//		cveMatches := cveRegex.FindAllString(url, -1)
//		exploitMatches := expRegex.FindAllString(url, -1)
//
//		if cveMatches != nil {
//			return cveMatches[1], nil
//		}
//		if exploitMatches != nil {
//			return "Exploit payload detected", nil
//		}
//	}
//	return "", nil
//}
