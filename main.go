package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/logrusorgru/aurora/v3"
	log "github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

type Config struct {
	engine       string `json:"engine"`
	Page         int    `json:"page"`
	FilterStatus string `json:"filterStatus"`
	FilterTime   string `json:"filterTime"`
	FromTime     string `json:"fromTime"`
	ToTime       string `json:"toTime"`
	TimePattern  string `json:"timePattern"`
	LogPattern   string `json:"logPattern"`
}

func init() {
	flag.StringVar(&engine, "e", "", "")
	flag.StringVar(&engine, "engine", "google", "")

	flag.IntVar(&page, "p", 1, "")
	flag.IntVar(&page, "page", 1, "")

	flag.Usage = func() {
		showBanner()
		h := []string{
			"Configuration Options for config.json:",
			"",
			"  engine:          Specifies the search engine to use for querying.",
			"                   Options: 'google', 'shodan', 'bing', 'duck', 'yahoo', 'ask'.",
			"                   Default: 'google'.",
			"",
			"  page:            Specifies the number of pages to search.",
			"                   Default: 1.",
			"",
			"  filterStatus:    Enables or disables filtering by HTTP status code.",
			"                   Options: 'True', 'False'.",
			"                   Default: 'True'.",
			"",
			"  filterTime:      Enables or disables filtering by time.",
			"                   Options: 'True', 'False'.",
			"                   Default: 'True'.",
			"",
			"  fromTime:        Start time for filtering logs. Optional.",
			"",
			"  toTime:          End time for filtering logs. Optional.",
			"",
			"  timePattern:     Regular expression pattern to extract date and time from log files.",
			"                   Example: '(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})'.",
			"  logPattern:     	Regular expression pattern to read log files.",
			"                   Default: '\\*\\.log'.",
			"",
			"Note: If any pattern is not specified in config.json, default values will be used.",
			"",
		}
		fmt.Fprintf(os.Stderr, "%s", aurora.Green(strings.Join(h, "\n")))
	}
	flag.Parse()

	engine = strings.ToLower(engine)

	maxLog := levels.LevelDebug
	if silent {
		maxLog = levels.LevelSilent
	}
	log.DefaultLogger.SetMaxLevel(maxLog)

	showBanner()
}

func main() {
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatal().Msgf("Failed to open config.json: %v\n", err)
		os.Exit(2)
	}
	defer configFile.Close()

	var config Config
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		log.Fatal().Msgf("Failed to parse config.json: %v\n", err)
	}

	uriMap := make(map[string]int)

	err = parseAccess(config, uriMap)
	if err != nil {
		log.Fatal().Msgf("Error filtering URIs and status codes: %v\n", err)
	}

	outputFile := "filtered_uris.csv"
	file, err := os.Create(outputFile)
	if err != nil {
		log.Fatal().Msgf("Failed to create output file: %v\n", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"URI", "Cnt"}); err != nil {
		log.Fatal().Msgf("Failed to write header to CSV: %v\n", err)
	}

	for uri, count := range uriMap {
		record := []string{uri, fmt.Sprintf("%d", count)}
		if err := writer.Write(record); err != nil {
			log.Fatal().Msgf("failed to write record to CSV: %v", err)
		}
	}
	queries := make([]string, 0, len(uriMap))
	for uri := range uriMap {
		queries = append(queries, fmt.Sprintf("allintext: %s cve-", uri))

	}
	uris := make(map[string]string)
	for uri := range uriMap {
		uris[uri] = ""
	}
	log.Info().Msgf("Start Querying...")
	log.Info().Msgf("Number of queries: %+v", len(uris))
	log.Info().Msgf("Page to get result : %s", strconv.Itoa(page))

	proxies := fetchUniqueProxies()
	if len(proxies) <= 0 {
		log.Warning().Msg("No proxy found!")
		os.Exit(2)
	} else {
		log.Info().Msgf("%d proxies found!", len(proxies))
		queryProcessor(proxies, queries, uris, engine, page, headers)
	}
}
