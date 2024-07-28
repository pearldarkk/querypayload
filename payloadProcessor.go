package main

import (
	"os"
	"regexp"
	"sync"

	log "github.com/projectdiscovery/gologger"
)

func queryProcessor(proxies []string, queries []string, uris map[string]string, engine string, page int, headers []string) (string, error) {
	var sus string
	var wg sync.WaitGroup
	proxiesMutex := sync.Mutex{}
	activeProxies := make(map[string]bool)

	for _, proxy := range proxies {
		activeProxies[proxy] = true
	}

	for _, q := range queries {
		wg.Add(1)
		go func(dork string) {
			defer wg.Done()
			var proxyToUse string

			proxiesMutex.Lock()
			for proxy := range activeProxies {
				proxyToUse = proxy
				break
			}
			proxiesMutex.Unlock()

			if proxyToUse == "" {
				log.Fatal().Msgf("No active proxies available")
				os.Exit(2)
			}

			opts := options{
				Query:   dork,
				Engine:  engine,
				Page:    page,
				Proxy:   proxyToUse,
				Headers: headers,
			}

			res, err := opts.getSearchResult()
			if err != nil {
				proxiesMutex.Lock()
				delete(activeProxies, proxyToUse)
				proxiesMutex.Unlock()
			} else {
				sus, err = checkPayload(res)
				if err != nil {
					log.Fatal().Msgf("Error checking payload: %v\n", err)
				} else {
					uris[dork] = sus
				}
			}
		}(q)
	}

	wg.Wait()
	return sus, nil
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
