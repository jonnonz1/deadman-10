package arweave

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to an Arweave gateway (or arlocal devnet) over HTTP.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient returns a client for the given gateway base URL (e.g.
// https://arweave.net or http://127.0.0.1:1985 for arlocal).
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Price returns the winston reward required to store numBytes.
func (c *Client) Price(numBytes int) (string, error) {
	body, err := c.get(fmt.Sprintf("/price/%d", numBytes))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// Anchor returns a recent transaction anchor for last_tx.
func (c *Client) Anchor() (string, error) {
	body, err := c.get("/tx_anchor")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// Submit signs nothing; it posts an already-signed transaction. It returns the
// transaction id on success.
func (c *Client) Submit(tx *Transaction) (string, error) {
	payload, err := tx.JSON()
	if err != nil {
		return "", err
	}
	resp, err := c.http.Post(c.baseURL+"/tx", "application/json", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("submit tx: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return tx.ID, nil
}

// Fetch retrieves the raw data stored at a transaction id.
func (c *Client) Fetch(txID string) ([]byte, error) {
	return c.get("/" + txID)
}

// get performs a GET and returns the body, erroring on non-2xx.
func (c *Client) get(path string) ([]byte, error) {
	resp, err := c.http.Get(c.baseURL + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	return b, nil
}
