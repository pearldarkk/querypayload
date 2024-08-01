package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"time"

	log "github.com/projectdiscovery/gologger"
)

func parseAccess(filePath string, config Config, uriMap map[string]int) error {
	uriPattern := `(?:GET|POST|CONNECT|TUNNEL|HEAD|PUT|DELETE|OPTIONS|TRACE|PATCH)\s([^\;\s]+)`
	statusPattern := `[\s\t](\d+)[\s\t]\d+[\s\t]`
	timePattern := config.TimePattern
	if timePattern == "" {
		timePattern = `(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`
	}
	uriRegex, _ := regexp.Compile(uriPattern)
	statusRegex, _ := regexp.Compile(statusPattern)
	timeRegex, _ := regexp.Compile(timePattern)

	// Handle time filtering input
	var fromTime, toTime time.Time
	if config.FromTime != "" {
		tempTime := config.FromTime
		if len(tempTime) == 4 {
			tempTime += "-01-01 00:00:00"
		} else if len(tempTime) == 7 {
			tempTime += "-01 00:00:00"
		} else if len(tempTime) == 10 {
			tempTime += " 00:00:00"
		} else if len(tempTime) == 13 {
			tempTime += ":00:00"
		} else if len(tempTime) == 16 {
			tempTime += ":00"
		}
		fromTimeParsed, err := time.Parse("2006-01-02 15:04:05", tempTime)
		if err != nil {
			return err
		}
		fromTime = fromTimeParsed
	}
	if config.ToTime != "" {
		tempTime := config.ToTime
		if len(tempTime) == 4 {
			tempTime += "-01-01 00:00:00"
		} else if len(tempTime) == 7 {
			tempTime += "-01 00:00:00"
		} else if len(tempTime) == 10 {
			tempTime += " 00:00:00"
		} else if len(tempTime) == 13 {
			tempTime += ":00:00"
		} else if len(tempTime) == 16 {
			tempTime += ":00"
		}
		toTimeParsed, err := time.Parse("2006-01-02 15:04:05", tempTime)
		if err != nil {
			return err
		}
		toTime = toTimeParsed
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		uriMatches := uriRegex.FindStringSubmatch(line)
		statusMatches := statusRegex.FindStringSubmatch(line)

		// if is valid access log
		if len(uriMatches) > 1 && len(statusMatches) > 1 {
			encodedURI := uriMatches[1]
			statusCode := statusMatches[1]

			// if has filterStatus enabled then only get 200 status code access log
			if !config.FilterStatus && statusCode != "200" {
				continue
			}

			// if has filterTime enabled then only get logs between fromTime and toTime
			if config.FromTime != "" || config.ToTime != "" {
				timeMatches := timeRegex.FindStringSubmatch(line)
				if len(timeMatches) > 1 {
					logTime, err := time.Parse("2006-01-02 15:04:05", timeMatches[1])
					if err != nil {
						log.Fatal().Msgf("Failed to parse time: %v\n", err)
						continue
					}

					if config.FromTime != "" && logTime.Before(fromTime) {
						continue
					}

					if config.ToTime != "" && logTime.After(toTime) {
						continue
					}
				}
			}
			uriMap[encodedURI]++
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func readAccess(config Config, uriMap map[string]int) error {
	if config.LogPattern == "" {
		config.LogPattern = "*.log"
	}
	files, err := filepath.Glob(config.LogPattern)
	if err != nil {
		return err
	}
	for _, file := range files {
		err := parseAccess(file, config, uriMap)
		if err != nil {
			return err
		}
	}

	return nil
}
