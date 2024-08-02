package main

import (
	"io"
	"net/http"
	"strings"
	"time"
)

func (opt *options) get(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	for _, h := range opt.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			continue
		}
		req.Header.Set(parts[0], parts[1])
	}
	var transport http.RoundTripper
	//if strings.HasPrefix(opt.Proxy, "socks5://") {
	//	proxyAddress := opt.Proxy[len("socks5://"):]
	//	dialer, err := proxylib.SOCKS5("tcp", proxyAddress, nil, proxylib.Direct)
	//	if err != nil {
	//		return "", err
	//	}
	//	transport = &http.Transport{
	//		Dial: dialer.Dial,
	//	}
	//} else {
	//	proxyURL, err := urllib.Parse(opt.Proxy)
	//	if err != nil {
	//		return "", err
	//	}
	//	transport = &http.Transport{
	//		Proxy: http.ProxyURL(proxyURL),
	//	}
	//}
	transport = http.DefaultTransport
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second}

	//req.Header.Add("User-Agent", "Go-HttpClient")
	req.Header.Add("Accept", "text/html")
	req.Header.Add("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	return string(data), nil
}
