package logging

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// Collector holds a fixed-size list of records
type Collector struct {
	mu         sync.Mutex
	records    []LogRecord
	maxSize    int
	endpoint   string
	httpClient *http.Client
	authHeader string
}

// NewCollector initializes and returns a new Collector
func NewCollector(maxSize int, endpoint, login, password string) *Collector {
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", login, password)))
	return &Collector{
		records:    make([]LogRecord, 0, maxSize),
		maxSize:    maxSize,
		endpoint:   endpoint,
		httpClient: &http.Client{},
		authHeader: "Basic " + auth,
	}
}

// CollectAndSend collects a new record. If the list reaches the maxSize, it sends the records to the configured endpoint and resets the list.
func (c *Collector) CollectAndSend(record LogRecord) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.records = append(c.records, record)

	if len(c.records) >= c.maxSize {
		if err := c.Send(); err != nil {
			return err
		}
		// Reset the list after sending
		c.records = c.records[:0]
	}

	return nil
}

// Send sends the list of records to the configured HTTP endpoint as JSON
func (c *Collector) Send() error {
	if len(c.records) == 0 {
		return nil // No records to send
	}

	jsonData, err := json.Marshal(c.records)
	if err != nil {
		return fmt.Errorf("failed to marshal records: %w", err)
	}

	req, err := http.NewRequest("POST", c.endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	// Set the content type and authorization headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.authHeader)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-200 status: %d %s", resp.StatusCode, resp.Status)
	}

	return nil
}
