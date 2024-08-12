package main

import (
	"encoding/csv"
	"fmt"
	"github.com/logrusorgru/aurora/v3"
	log "github.com/projectdiscovery/gologger"
	urllib "net/url"
	"os"
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

func outURI(outFile string, dat map[uridat]int) {
	file, err := os.Create(outFile)
	if err != nil {
		log.Fatal().Msgf("Failed to create output file: %v\n", err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	if err := writer.Write([]string{"URI", "Cnt", "Method"}); err != nil {
		log.Fatal().Msgf("Failed to write header: %v\n", err)
	}
	for d, c := range dat {
		line := []string{d.method, d.uri, fmt.Sprintf("%d", c)}
		if err := writer.Write(line); err != nil {
			log.Fatal().Msgf("Failed to write line: %v\n", err)
		}
	}
}
