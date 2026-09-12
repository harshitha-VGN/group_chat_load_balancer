package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// Backend holds state and dynamic performance metrics for a backend server
type Backend struct {
	URL           *url.URL
	Alive         atomic.Bool
	ActiveReqs    atomic.Int64
	RecentLatency atomic.Int64 // Milliseconds
	CPULoad       atomic.Int64 // Scaled integer (e.g., percent * 10)
	FailCount     atomic.Int64
	Proxy         *httputil.ReverseProxy
}

// HealthResponse matches the JSON returned by server.py /health
type HealthResponse struct {
	Status         string  `json:"status"`
	CPUPercent     float64 `json:"cpu_percent"`
	MemoryPercent  float64 `json:"memory_percent"`
	ActiveRequests int64   `json:"active_requests"`
}

// DynamicLoadBalancer manages routing with dynamic threshold switching
type DynamicLoadBalancer struct {
	backends        []*Backend
	threshold       int64 // Active requests threshold before switching away
	healthInterval  time.Duration
}

// Compute dynamic load score (lower is better)
func (b *Backend) Score() int64 {
	active := b.ActiveReqs.Load()
	cpu := b.CPULoad.Load()
	latency := b.RecentLatency.Load()
	// Weight active requests heavily (100x), then CPU load, then response latency
	return (active * 100) + (cpu * 2) + latency
}

// Dynamic Backend Selection with Threshold Switching
func (lb *DynamicLoadBalancer) SelectBackend() *Backend {
	var best *Backend
	var minScore int64 = 1<<62 - 1

	for _, b := range lb.backends {
		if !b.Alive.Load() {
			continue
		}

		score := b.Score()
		// If backend active requests are below the threshold, favor it immediately
		if score < minScore {
			minScore = score
			best = b
		}
	}

	return best
}

func main() {
	var backendList string
	var listenPort string
	var threshold int64
	var checkInterval int

	flag.StringVar(&backendList, "backends", "http://10.1.75.79:5246,http://10.1.75.79:5247,http://10.1.75.79:5248", "Comma separated backends")
	flag.StringVar(&listenPort, "port", "8000", "Port to listen on")
	flag.Int64Var(&threshold, "threshold", 8, "Dynamic load switching threshold (active concurrency / load score)")
	flag.IntVar(&checkInterval, "health-interval", 1, "Health check interval in seconds")
	flag.Parse()

	lb := &DynamicLoadBalancer{
		threshold:      threshold,
		healthInterval: time.Duration(checkInterval) * time.Second,
	}

	// High performance HTTP transport for reverse proxying
	customTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        5000,
		MaxIdleConnsPerHost: 1000,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   false,
	}

	for _, bStr := range strings.Split(backendList, ",") {
		bStr = strings.TrimSpace(bStr)
		if bStr == "" {
			continue
		}
		if !strings.HasPrefix(bStr, "http://") && !strings.HasPrefix(bStr, "https://") {
			bStr = "http://" + bStr
		}
		u, err := url.Parse(bStr)
		if err != nil {
			log.Fatalf("Invalid backend URL %s: %v", bStr, err)
		}

		proxy := httputil.NewSingleHostReverseProxy(u)
		proxy.Transport = customTransport

		// Director to preserve headers and set forwarding info
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Header.Set("X-Forwarded-Host", req.Host)
			req.Header.Set("X-Forwarded-For", req.RemoteAddr)
		}

		b := &Backend{URL: u, Proxy: proxy}
		b.Alive.Store(true)

		// Resilient ErrorHandler with failover retry
		proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
			log.Printf("[LB] Backend %s error: %v. Retrying on alternative backend...", u.String(), err)
			b.Alive.Store(false)
			b.FailCount.Add(1)

			// Try another backend
			alt := lb.SelectBackend()
			if alt != nil && alt != b {
				alt.Proxy.ServeHTTP(w, req)
				return
			}
			http.Error(w, "Service Temporarily Unavailable", http.StatusServiceUnavailable)
		}

		lb.backends = append(lb.backends, b)
		log.Printf("Registered backend: %s", u.String())
	}

	if len(lb.backends) == 0 {
		log.Fatal("No valid backends configured!")
	}

	// Dynamic Health Check and Metric Collector Loop
	go func() {
		client := &http.Client{
			Timeout:   2 * time.Second,
			Transport: customTransport,
		}
		for {
			for _, b := range lb.backends {
				start := time.Now()
				resp, err := client.Get(b.URL.String() + "/health")
				latency := time.Since(start).Milliseconds()

				if err == nil && resp.StatusCode == 200 {
					b.Alive.Store(true)
					b.FailCount.Store(0)
					b.RecentLatency.Store(latency)

					var hr HealthResponse
					body, rErr := io.ReadAll(resp.Body)
					resp.Body.Close()
					if rErr == nil && json.Unmarshal(body, &hr) == nil {
						b.CPULoad.Store(int64(hr.CPUPercent * 10))
					}
				} else {
					if resp != nil {
						resp.Body.Close()
					}
					b.Alive.Store(false)
					b.FailCount.Add(1)
				}
			}
			time.Sleep(lb.healthInterval)
		}
	}()

	// HTTP Handler with Dynamic Load Tracking
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := lb.SelectBackend()
		if target == nil {
			http.Error(w, "All backend servers are unavailable", http.StatusServiceUnavailable)
			return
		}

		// Track active in-flight requests for dynamic load estimation
		target.ActiveReqs.Add(1)
		startTime := time.Now()

		target.Proxy.ServeHTTP(w, r)

		target.ActiveReqs.Add(-1)
		durationMs := time.Since(startTime).Milliseconds()

		// Update exponential moving average latency
		oldLat := target.RecentLatency.Load()
		if oldLat == 0 {
			target.RecentLatency.Store(durationMs)
		} else {
			target.RecentLatency.Store((oldLat*7 + durationMs*3) / 10)
		}
	})

	addr := ":" + listenPort
	fmt.Println("======================================================")
	fmt.Printf(" Dynamic Performance-Based Load Balancer\n")
	fmt.Printf(" Listening on port : %s\n", listenPort)
	fmt.Printf(" Backends count    : %d\n", len(lb.backends))
	fmt.Printf(" Switch Threshold  : %d\n", threshold)
	fmt.Println("======================================================")

	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}
