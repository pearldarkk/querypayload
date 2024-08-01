package main

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"sync"
	log "github.com/projectdiscovery/gologger"
)

var ProxyFetch = struct {
	ListProtocol []string
	URLs         []string
}{
	ListProtocol: []string{"http", "socks5"},
	URLs: []string{
		"https://openproxylist.xyz/{protocol}.txt",
		"https://proxyspace.pro/{protocol}.txt",
		"https://www.proxy-list.download/api/v1/get?type={protocol}",
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/{protocol}.txt",
		"https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/{protocol}.txt",
		"https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/{protocol}_proxies.txt",
		"https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/{protocol}.txt",
		"https://raw.githubusercontent.com/mmpx12/proxy-list/master/{protocol}.txt",
		"https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/{protocol}.txt",
		"https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/{protocol}/{protocol}.txt",
		"https://raw.githubusercontent.com/prxchk/proxy-list/main/{protocol}.txt",
		"https://raw.githubusercontent.com/roosterkid/openproxylist/main/{protocol}_RAW.txt", // need upper case
		"https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/{protocol}.txt",   // http only
		"https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/{protocol}.txt",
		"https://raw.githubusercontent.com/zevtyardt/proxy-list/main/{protocol}.txt",
		"https://raw.githubusercontent.com/zloi-user/hideip.me/main/{protocol}.txt",
	},
}

func fetchProxies(url string, wg *sync.WaitGroup, protocol string, proxiesChan chan<- string) {
	defer wg.Done()

	resp, err := http.Get(url)
	if err != nil {
		log.Info().Msgf("Failed to fetch %s: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Info().Msgf("Failed to read response body from %s: %v\n", url, err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		proxy := scanner.Text()
		proxiesChan <- protocol + "://" + proxy
	}

	if err := scanner.Err(); err != nil {
		log.Info().Msgf("Error reading proxy list from %s: %v\n", url, err)
	}
}

func fetchUniqueProxies() []string {
	var wg sync.WaitGroup
	proxiesChan := make(chan string, 1000)
	proxyURLs := make(map[string]bool)

	for _, proto := range ProxyFetch.ListProtocol {
		for _, urlTemplate := range ProxyFetch.URLs {
			url := strings.ReplaceAll(urlTemplate, "{protocol}", proto)
			if proto == "http" && strings.Contains(url, "http_RAW.txt") {
				continue
			}
			wg.Add(1)
			go fetchProxies(url, &wg, proto, proxiesChan)
		}
	}

	go func() {
		wg.Wait()
		close(proxiesChan)
	}()

	for proxy := range proxiesChan {
		proxyURLs[proxy] = true
	}

	proxiesList := make([]string, 0, len(proxyURLs))
	for proxy := range proxyURLs {
		proxiesList = append(proxiesList, proxy)
	}

	return proxiesList
}
