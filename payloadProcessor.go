package main

import (
	"regexp"
	"sync"

	log "github.com/projectdiscovery/gologger"
)

func queryProcessor(proxies []string, queries []string, uris map[string]string, engine string, page int, headers []string) (string, error) {
	type queryResult struct {
		dork string
		sus  string
		err  error
	}

	resultChan := make(chan queryResult, len(queries))
	proxyChan := make(chan string, len(proxies))

	for _, proxy := range proxies {
		proxyChan <- proxy
	}

	var wg sync.WaitGroup
	for _, q := range queries {
		wg.Add(1)
		go func(dork string) {
			defer wg.Done()

			proxyToUse := <-proxyChan

			opts := options{
				Query:   dork,
				Engine:  engine,
				Page:    page,
				Proxy:   proxyToUse,
				Headers: headers,
			}

			res, err := opts.getSearchResult()
			if err != nil {
				log.Error().Msgf("Failed to get search result with proxy %s: %v\n", proxyToUse, err)
				resultChan <- queryResult{dork: dork, err: err}
				proxyChan <- proxyToUse
				return
			}

			result, err := checkPayload(res)
			if err != nil {
				log.Error().Msgf("Error checking payload: %v\n", err)
				resultChan <- queryResult{dork: dork, err: err}
				proxyChan <- proxyToUse
				return
			}

			resultChan <- queryResult{dork: dork, sus: result}
			proxyChan <- proxyToUse
		}(q)
	}

	wg.Wait()
	close(resultChan)

	var finalSus string
	for res := range resultChan {
		if res.err != nil {
			continue
		}
		uris[res.dork] = res.sus
		if finalSus == "" {
			finalSus = res.sus
		}
	}

	return finalSus, nil
}

func checkPayload(urls []string) (string, error) {
	cvePattern := `(?i)CVE-\d{4,}-\d{4,}`
	exp := `exploit`
	cveRegex, err := regexp.Compile(cvePattern)
	if err != nil {
		return "", err
	}
	expRegex, err := regexp.Compile(exp)
	if err != nil {
		return "", err
	}

	for _, url := range urls {
		cveMatches := cveRegex.FindAllString(url, -1)
		exploitMatches := expRegex.FindAllString(url, -1)

		if cveMatches != nil {
			return cveMatches[1], nil
		}
		if exploitMatches != nil {
			return "Exploit payload detected", nil
		}
	}
	return "", nil
}
