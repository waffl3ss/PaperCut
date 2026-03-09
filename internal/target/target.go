package target

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Stream represents a lazy stream of target IPs with a known (or estimated) total count.
type Stream struct {
	IPs   <-chan string
	Total int
	stop  context.CancelFunc
}

// Stop cancels IP generation early (e.g. on Ctrl+C).
func (s *Stream) Stop() {
	if s.stop != nil {
		s.stop()
	}
}

// NewStream parses the input and returns a lazily-generated stream of IPs.
// Nothing is held in memory — IPs are produced on demand.
func NewStream(input string) (*Stream, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("empty target input")
	}

	// Expand ~ to home directory
	if input == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			input = home
		}
	} else if strings.HasPrefix(input, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			input = filepath.Join(home, input[2:])
		}
	}

	// Single IP
	if ip := net.ParseIP(input); ip != nil {
		ch := make(chan string, 1)
		ch <- ip.String()
		close(ch)
		return &Stream{IPs: ch, Total: 1}, nil
	}

	// Comma-separated list (checked before CIDR/file since parts may contain those)
	if strings.Contains(input, ",") {
		return streamCommaList(input)
	}

	// CIDR — only if it actually parses as a valid CIDR
	if strings.Contains(input, "/") {
		if _, _, err := net.ParseCIDR(input); err == nil {
			return streamCIDR(input)
		}
	}

	// File
	if info, err := os.Stat(input); err == nil && !info.IsDir() {
		return streamFile(input)
	}

	// Hostname
	if !strings.ContainsAny(input, " \t\n") {
		ch := make(chan string, 1)
		ch <- input
		close(ch)
		return &Stream{IPs: ch, Total: 1}, nil
	}

	return nil, fmt.Errorf("unable to parse target %q: not a valid IP, CIDR, or file path", input)
}

func streamCommaList(input string) (*Stream, error) {
	parts := strings.Split(input, ",")

	// First pass: count totals and collect valid parts
	total := 0
	var validParts []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		validParts = append(validParts, p)

		if ip := net.ParseIP(p); ip != nil {
			total++
			continue
		}
		if strings.Contains(p, "/") {
			_, network, err := net.ParseCIDR(p)
			if err == nil {
				total += cidrHostCount(network)
				continue
			}
		}
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			n, err := countFileTargets(p)
			if err == nil {
				total += n
				continue
			}
		}
		// Hostname or other — count as 1
		total++
	}

	if len(validParts) == 0 {
		return nil, fmt.Errorf("no valid targets in comma-separated list")
	}

	// Single valid part — delegate directly
	if len(validParts) == 1 {
		return NewStream(validParts[0])
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan string, 256)

	go func() {
		defer close(ch)
		for _, p := range validParts {
			sub, err := NewStream(p)
			if err != nil {
				continue
			}
			for ip := range sub.IPs {
				select {
				case <-ctx.Done():
					sub.Stop()
					return
				case ch <- ip:
				}
			}
		}
	}()

	return &Stream{IPs: ch, Total: total, stop: cancel}, nil
}

func streamCIDR(cidr string) (*Stream, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	total := cidrHostCount(network)
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan string, 256)

	go func() {
		defer close(ch)
		ip := cloneIP(network.IP.Mask(network.Mask))
		ones, bits := network.Mask.Size()
		prefixLen := bits - ones

		if prefixLen >= 2 {
			// /30 and larger: skip network (first) and broadcast (last)
			totalWithNetBroadcast := total + 2
			for i := 0; i < totalWithNetBroadcast; i++ {
				if i == 0 || i == totalWithNetBroadcast-1 {
					incIP(ip)
					continue
				}
				select {
				case <-ctx.Done():
					return
				case ch <- ip.String():
				}
				incIP(ip)
			}
		} else {
			// /31 (2 addresses, both usable per RFC 3021) or /32 (single host)
			for i := 0; i < total; i++ {
				select {
				case <-ctx.Done():
					return
				case ch <- ip.String():
				}
				incIP(ip)
			}
		}
	}()

	return &Stream{IPs: ch, Total: total, stop: cancel}, nil
}

func streamFile(path string) (*Stream, error) {
	// First pass: count total targets (fast, just counts lines)
	total, err := countFileTargets(path)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan string, 256)

	go func() {
		defer close(ch)
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Each line can be an IP, CIDR, or hostname
			lineStream, err := NewStream(line)
			if err != nil {
				continue
			}
			for ip := range lineStream.IPs {
				select {
				case <-ctx.Done():
					lineStream.Stop()
					return
				case ch <- ip:
				}
			}
		}
	}()

	return &Stream{IPs: ch, Total: total, stop: cancel}, nil
}

// countFileTargets does a fast pre-scan of a file to estimate total IPs.
func countFileTargets(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open target file: %w", err)
	}
	defer f.Close()

	total := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "/") {
			_, network, err := net.ParseCIDR(line)
			if err == nil {
				total += cidrHostCount(network)
				continue
			}
		}

		// Single IP, hostname, or unparseable — count as 1
		total++
	}

	if total == 0 {
		return 0, fmt.Errorf("no valid targets found in file %q", path)
	}

	return total, scanner.Err()
}

// cidrHostCount returns the number of usable host IPs in a network.
func cidrHostCount(network *net.IPNet) int {
	ones, bits := network.Mask.Size()
	prefixLen := bits - ones

	if prefixLen >= 63 {
		return math.MaxInt64
	}

	size := new(big.Int).Lsh(big.NewInt(1), uint(prefixLen))
	total := int(size.Int64())

	// /32 = 1 host, /31 = 2 hosts (RFC 3021, both usable)
	// /30 and larger: subtract network + broadcast
	if prefixLen >= 2 {
		total -= 2
	}

	return total
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
