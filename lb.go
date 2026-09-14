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

type Backend struct {
	URL           *url.URL
	Alive         atomic.Bool
	ActiveReqs    atomic.Int64
	RecentLatency atomic.Int64
	CPULoad       atomic.Int64
	FailCount     atomic.Int64
	Proxy         *httputil.ReverseProxy
}

type HealthResponse struct {
	Status         string  `json:"status"`
	CPUPercent     float64 `json:"cpu_percent"`
	MemoryPercent  float64 `json:"memory_percent"`
	ActiveRequests int64   `json:"active_requests"`
}

type DynamicLoadBalancer struct {
	backends       []*Backend
	threshold      int64
	healthInterval time.Duration
}

func (b *Backend) Score() int64 {
	active := b.ActiveReqs.Load()
	cpu := b.CPULoad.Load()
	latency := b.RecentLatency.Load()
	return (active * 200) + (cpu * 3) + latency
}

func (lb *DynamicLoadBalancer) SelectBackend() *Backend {
	var best *Backend
	var minScore int64 = 1<<62 - 1

	// 1. Try to find the best alive backend
	for _, b := range lb.backends {
		if !b.Alive.Load() {
			continue
		}
		score := b.Score()
		if score < minScore {
			minScore = score
			best = b
		}
	}

	// 2. Resilience Fallback: if all marked dead temporarily, pick lowest active/fail count
	if best == nil && len(lb.backends) > 0 {
		for _, b := range lb.backends {
			score := b.ActiveReqs.Load()*100 + b.FailCount.Load()*50
			if score < minScore {
				minScore = score
				best = b
			}
		}
	}

	return best
}

func main() {
	var backendList string
	var listenPort string
	var threshold int64

	flag.StringVar(&backendList, "backends", "http://10.1.75.79:5246,http://10.1.75.79:5247,http://10.1.75.79:5248", "Comma separated backends")
	flag.StringVar(&listenPort, "port", "6000", "Port to listen on")
	flag.Int64Var(&threshold, "threshold", 8, "Dynamic load switching threshold")
	flag.Parse()

	lb := &DynamicLoadBalancer{
		threshold:      threshold,
		healthInterval: 500 * time.Millisecond,
	}

	customTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        10000,
		MaxIdleConnsPerHost: 2000,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   true,
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

		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Header.Set("X-Forwarded-Host", req.Host)
			req.Header.Set("X-Forwarded-For", req.RemoteAddr)
			req.Header.Set("Connection", "close")
		}

		b := &Backend{URL: u, Proxy: proxy}
		b.Alive.Store(true)

		proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
			b.FailCount.Add(1)
			http.Error(w, "Service Temporarily Unavailable", http.StatusServiceUnavailable)
		}

		lb.backends = append(lb.backends, b)
	}

	go func() {
		client := &http.Client{
			Timeout:   5 * time.Second,
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
					fails := b.FailCount.Add(1)
					if fails > 10 {
						b.Alive.Store(false)
					}
				}
			}
			time.Sleep(lb.healthInterval)
		}
	}()


	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dynamic Least-Loaded Proxying to Backends
		// All /feed, /message, /health, /sync routes are handled by backends
		target := lb.SelectBackend()
		if target == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"all backends unavailable"}`))
			return
		}

		target.ActiveReqs.Add(1)
		startTime := time.Now()
		target.Proxy.ServeHTTP(w, r)
		target.ActiveReqs.Add(-1)
		durationMs := time.Since(startTime).Milliseconds()

		oldLat := target.RecentLatency.Load()
		if oldLat == 0 {
			target.RecentLatency.Store(durationMs)
		} else {
			target.RecentLatency.Store((oldLat*7 + durationMs*3) / 10)
		}
	})

	fmt.Println("======================================================")
	fmt.Printf(" Ultra-High-Performance Dynamic Load Balancer\n")
	fmt.Printf(" Listening on port : %s\n", listenPort)
	fmt.Printf(" Backends count    : %d\n", len(lb.backends))
	fmt.Println("======================================================")

	server := &http.Server{
		Addr:         ":" + listenPort,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}

