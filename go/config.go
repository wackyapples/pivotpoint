package main

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// TOMLData represents the parsed TOML data structure
type TOMLData map[string]any

// RedirectConfig represents a redirect rule configuration
type RedirectConfig struct {
	SourceDomain string
	TargetURL    string
	RedirectType int
	PreservePath bool
	HTTPSFirst   bool
}

// CertConfig represents a certificate configuration
type CertConfig struct {
	Domain   string
	CertFile string
	KeyFile  string
}

// ParseConfig reads TOML data from a reader and returns a map of the parsed data
func ParseConfig(r io.Reader) (TOMLData, error) {
	data := make(TOMLData)
	currentSection := data
	// var currentArray []any
	var inArray bool
	var arrayKey string
	var currentArrayItem TOMLData

	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle array start
		if strings.HasPrefix(line, "[[") && strings.HasSuffix(line, "]]") {
			arrayKey = line[2 : len(line)-2]
			arrayKey = strings.TrimSpace(arrayKey)
			if _, exists := data[arrayKey]; !exists {
				data[arrayKey] = make([]any, 0)
			}
			currentArrayItem = make(TOMLData)
			inArray = true
			continue
		}

		// Handle sections
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sectionName := line[1 : len(line)-1]
			sectionName = strings.TrimSpace(sectionName)
			section := make(TOMLData)
			data[sectionName] = section
			currentSection = section
			inArray = false
			continue
		}

		// Handle key-value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue // Skip invalid lines
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Parse the value
		parsedValue, err := parseValue(value)
		if err != nil {
			return nil, fmt.Errorf("line %d: error parsing value for key %s: %v", lineNum, key, err)
		}

		if inArray {
			currentArrayItem[key] = parsedValue
			// Get the current array
			array := data[arrayKey].([]any)
			// If this is the first key-value pair, append the new map
			if len(currentArrayItem) == 1 {
				array = append(array, currentArrayItem)
				data[arrayKey] = array
			}
		} else {
			currentSection[key] = parsedValue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return data, nil
}

// parseValue converts a string value to the appropriate type
func parseValue(value string) (any, error) {
	// Remove quotes for strings
	if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
		return value[1 : len(value)-1], nil
	}

	// Try parsing as boolean
	switch v := strings.ToLower(value); v {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	}

	// Try parsing as integer
	if i, err := strconv.ParseInt(value, 10, 64); err == nil {
		return i, nil
	}

	// Try parsing as float
	if f, err := strconv.ParseFloat(value, 64); err == nil {
		return f, nil
	}

	// Return as string if no other type matches
	return value, nil
}

// ParseRedirectConfigs parses redirect configurations from TOML data
func ParseRedirectConfigs(data TOMLData) ([]RedirectConfig, error) {
	redirectsArray, ok := data["redirects"].([]any)
	if !ok {
		return nil, fmt.Errorf("redirects section not found or invalid")
	}

	var configs []RedirectConfig
	for i, item := range redirectsArray {
		itemMap, ok := item.(TOMLData)
		if !ok {
			return nil, fmt.Errorf("invalid redirect config at index %d", i)
		}

		// Safely extract values with type assertions
		sourceDomain, ok := itemMap["source_domain"].(string)
		if !ok {
			return nil, fmt.Errorf("missing or invalid source_domain at index %d", i)
		}

		targetURL, ok := itemMap["target_url"].(string)
		if !ok {
			return nil, fmt.Errorf("missing or invalid target_url at index %d", i)
		}

		config := RedirectConfig{
			SourceDomain: sourceDomain,
			TargetURL:    targetURL,
			RedirectType: 301,   // default value
			PreservePath: true,  // default value
			HTTPSFirst:   false, // default value
		}

		// Optional fields with type assertions
		if redirectType, ok := itemMap["type"].(int64); ok {
			config.RedirectType = int(redirectType)
		}
		if preservePath, ok := itemMap["preserve_path"].(bool); ok {
			config.PreservePath = preservePath
		}
		if httpsFirst, ok := itemMap["https_first"].(bool); ok {
			config.HTTPSFirst = httpsFirst
		}

		configs = append(configs, config)
	}

	return configs, nil
}

// ParseCertConfigs parses certificate configurations from TOML data
func ParseCertConfigs(data TOMLData) ([]CertConfig, error) {
	certsArray, ok := data["certificates"].([]any)
	if !ok {
		return nil, fmt.Errorf("certificates section not found or invalid")
	}

	var configs []CertConfig
	for i, item := range certsArray {
		itemMap, ok := item.(TOMLData)
		if !ok {
			return nil, fmt.Errorf("invalid certificate config at index %d", i)
		}

		domain, ok := itemMap["domain"].(string)
		if !ok {
			return nil, fmt.Errorf("missing or invalid domain at index %d", i)
		}

		certFile, ok := itemMap["cert_file"].(string)
		if !ok {
			return nil, fmt.Errorf("missing or invalid cert_file at index %d", i)
		}

		keyFile, ok := itemMap["key_file"].(string)
		if !ok {
			return nil, fmt.Errorf("missing or invalid key_file at index %d", i)
		}
		
		config := CertConfig{
			Domain:   domain,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		configs = append(configs, config)
	}

	return configs, nil
}
