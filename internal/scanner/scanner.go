package scanner

import (
	"context"
	"strings"
	"sync"
	"time"

	"papercut/internal/output"
	"papercut/internal/workspace"
)

// ScanConfig holds the parameters for a scan operation.
type ScanConfig struct {
	Targets     <-chan string  // streamed lazily, not a slice
	Port        int
	Workers     int
	Timeout     time.Duration
	Rate        int           // max connections per second, 0 = unlimited
	Proxy       string        // SOCKS5 proxy for TCP connections (socks5://host:port)
	WorkspaceID int64
	Quiet       bool
	OnResult    func(result *PJLResult) // called per-result for live output
	OnError     func(ip string)         // called when a host doesn't respond
}

// Run executes a concurrent scan against all targets from the stream.
func Run(ctx context.Context, cfg *ScanConfig) ([]*PJLResult, error) {
	if cfg.Port == 0 {
		cfg.Port = 9100
	}
	if cfg.Workers == 0 {
		cfg.Workers = 10
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 3 * time.Second
	}

	// Internal buffered channel for the worker pool
	work := make(chan string, cfg.Workers*2)
	results := make(chan *PJLResult, cfg.Workers*2)
	var wg sync.WaitGroup

	// Log first proxy error so silent failures are visible
	var proxyErrOnce sync.Once

	// Start workers
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range work {
				select {
				case <-ctx.Done():
					return
				default:
				}

				result, err := QueryPJL(ip, cfg.Port, cfg.Timeout, cfg.Proxy)
				if err != nil {
					// Surface first proxy setup error so user knows the proxy is misconfigured.
					// Only match errors that mean the proxy itself is unreachable or rejecting us,
					// NOT normal target timeouts/refusals routed through a working proxy.
					if cfg.Proxy != "" && isProxySetupError(err.Error()) {
						proxyErrOnce.Do(func() {
							output.Error("Proxy error: %v", err)
							output.Warn("All scan traffic may be failing — check your proxy settings")
						})
					}
					if cfg.OnError != nil {
						cfg.OnError(ip)
					}
					continue
				}
				results <- result
			}
		}()
	}

	// Collect results
	var collected []*PJLResult
	var collectWG sync.WaitGroup
	collectWG.Add(1)
	go func() {
		defer collectWG.Done()
		for r := range results {
			collected = append(collected, r)
			if cfg.OnResult != nil {
				cfg.OnResult(r)
			}
		}
	}()

	// Feed targets from the stream into the worker pool, with optional rate limiting
	var ticker *time.Ticker
	if cfg.Rate > 0 {
		interval := time.Second / time.Duration(cfg.Rate)
		if interval <= 0 {
			interval = time.Microsecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	for ip := range cfg.Targets {
		if ticker != nil {
			select {
			case <-ctx.Done():
				goto done
			case <-ticker.C:
			}
		}

		select {
		case <-ctx.Done():
			goto done
		case work <- ip:
		}
	}

done:
	close(work)
	wg.Wait()
	close(results)
	collectWG.Wait()

	// Store results in database
	if cfg.WorkspaceID > 0 {
		for _, r := range collected {
			sr := &workspace.ScanResult{
				WorkspaceID:  cfg.WorkspaceID,
				IP:           r.IP,
				Port:         r.Port,
				Manufacturer: r.Manufacturer,
				Model:        r.Model,
				PJLRawID:     r.RawID,
				PJLRawStatus: r.RawStatus,
			}
			if err := workspace.InsertScanResult(sr); err != nil {
				output.Warn("Failed to store result for %s: %v", r.IP, err)
			}
		}
	}

	return collected, nil
}

// isProxySetupError returns true if the error indicates the proxy itself is
// unreachable or misconfigured. Returns false for normal target-level failures
// (timeouts, connection refused) that happen through a working proxy.
func isProxySetupError(msg string) bool {
	indicators := []string{
		"proxy connect:",            // can't reach the proxy host at all
		"socks5 handshake:",         // SOCKS5 handshake failed (proxy rejected greeting)
		"socks5 auth not supported", // proxy requires auth we don't offer
		"socks4 cannot resolve",     // DNS resolution failed for SOCKS4
		"socks4 does not support",   // IPv6 on SOCKS4
	}
	for _, s := range indicators {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
