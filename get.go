package main

import (
	"io"
	"net/http"
	"strings"

	"ktbs.dev/mubeng/pkg/mubeng"
)

func (opt *options) get(url string) string {
	req, err := http.NewRequest("GET", url, nil)
	for _, h := range opt.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			continue
		}
		req.Header.Set(parts[0], parts[1])
	}
	isError(err)

	client.Transport, err = mubeng.Transport(opt.Proxy)
	isError(err)

	req.Header.Add("Connection", "close")

	resp, err := client.Do(req)
	isError(err)
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	body := string(data)
	return body
}
