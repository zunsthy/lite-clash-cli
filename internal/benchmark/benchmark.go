package benchmark

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"lite-clash-cli/internal/trojan"
)

const (
	URL     = "http://cp.cloudflare.com/generate_204"
	Timeout = 5 * time.Second
)

type Result struct {
	Index   int
	Name    string
	DelayMS int64
	Err     error
}

func All(ctx context.Context, proxies []trojan.Config, unifiedDelay bool) []Result {
	results := make([]Result, len(proxies))
	var wait sync.WaitGroup
	wait.Add(len(proxies))

	for index, proxyConfig := range proxies {
		go func() {
			defer wait.Done()
			result := Result{Index: index + 1, Name: proxyConfig.Name}
			testContext, cancel := context.WithTimeout(ctx, Timeout)
			defer cancel()
			result.DelayMS, result.Err = test(testContext, proxyConfig, unifiedDelay)
			results[index] = result
		}()
	}

	wait.Wait()
	return results
}

func test(ctx context.Context, proxyConfig trojan.Config, unifiedDelay bool) (int64, error) {
	target, err := targetAddress(URL)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	connection, err := trojan.NewDialer(proxyConfig).DialTCP(ctx, target)
	if err != nil {
		return 0, err
	}
	defer connection.Close()

	request, err := http.NewRequestWithContext(ctx, http.MethodHead, URL, nil)
	if err != nil {
		return 0, err
	}
	transport := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return connection, nil
		},
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer transport.CloseIdleConnections()

	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	_ = response.Body.Close()

	if unifiedDelay {
		secondStart := time.Now()
		secondResponse, secondErr := client.Do(request)
		if secondErr == nil {
			_ = secondResponse.Body.Close()
			start = secondStart
		}
	}

	delay := time.Since(start) / time.Millisecond
	if delay == 0 {
		return 0, errors.New("measured delay is zero")
	}
	return int64(delay), nil
}

func targetAddress(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse benchmark URL: %w", err)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", errors.New("benchmark URL has no host")
	}
	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("unsupported benchmark URL scheme %q", parsed.Scheme)
		}
	}
	return net.JoinHostPort(host, port), nil
}
