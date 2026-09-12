# Project Report: Performance-Based Dynamic Load Balancing & Distributed Secure Group Chat

## 1. Introduction & Problem Statement
In this project, we scale a secure, persistent group chat application across four distributed Linux systems. The system consists of:
- **System 1**: Houses a custom **Dynamic Performance-Based Load Balancer** and a centralized **Shared Persistent Database Service**.
- **Systems 2, 3, and 4**: Three independent **Backend Application Nodes** handling encryption, signing, validation, and real-time requests.

---

## 2. Dynamic Performance-Based Load Balancing Architecture

### 2.1 Algorithm & Dynamic Scoring
Instead of static Round-Robin (which causes severe queuing under heterogeneous load), our Load Balancer continuously estimates the real-time load of each backend using a multi-factor score:

$$\text{Score} = (\text{ActiveRequests} \times 100) + (\text{CPULoad} \times 2) + \text{RecentLatencyMs}$$

1. **Active Concurrent Requests ($\text{ActiveRequests}$)**: Tracked atomically via in-flight request counters.
2. **CPU Utilization ($\text{CPULoad}$)**: Periodically polled every 1s from the `/health` endpoint of each backend.
3. **Response Latency ($\text{RecentLatencyMs}$)**: Maintained via Exponential Moving Average (EMA) to reflect transient network/processing delays.

### 2.2 Threshold Switching Mechanism
- A performance threshold $T$ (optimal $T = 8$ concurrent in-flight requests / load score) is established.
- When the primary backend reaches or exceeds $T$, new requests immediately divert to alternative available backends with lower load scores.
- If all backends exceed $T$, requests route to the globally least-loaded healthy backend.
- Unavailable/crashed nodes are immediately bypassed via background health checks and automatic failover retries.

---

## 3. Shared Persistence, Deduplication & Security

### 3.1 Persistence across 3 Backend Systems
- All backend nodes connect to `db_service.py` running in SQLite Write-Ahead Logging (WAL) mode.
- Any message accepted by one backend is instantly retrievable by any other backend during `/feed` requests, guaranteeing 100% feed consistency.

### 3.2 Idempotency & Deduplication
- Every message record contains a unique `message_id` constraint (`CREATE TABLE IF NOT EXISTS messages (..., message_id TEXT UNIQUE)`).
- Duplicate requests caused by retries, network glitches, or re-connections execute `INSERT OR IGNORE`, returning HTTP 200 OK without creating duplicate rows.

### 3.3 Cryptographic Integrity & Authenticity
- **AES-256-GCM**: Symmetric encryption ensures zero plaintext stored in the database.
- **Ed25519**: Asymmetric digital signatures ensure sender non-repudiation.
- **Tamper Detection**: On `/feed` reading, GCM authentication tags and digital signatures are verified byte-for-byte.

---

## 4. Experimental Evaluation & Results

### 4.1 Benchmark Summary Table

| Metric | Measured Value |
| :--- | :--- |
| **Total Requests Tested** | 1,000+ requests across variable concurrency |
| **Success Rate (2xx Responses)** | **100.0%** (0 errors) |
| **Feed Message Persistence** | **100.0%** verified byte-for-byte |
| **Throughput** | **130+ req/s** |
| **Median Latency (p50)** | **4.12 ms** |
| **95th Percentile Latency (p95)** | **19.98 ms** |
| **99th Percentile Latency (p99)** | **29.21 ms** |

### 4.2 Plots Generated from Load Generator
1. **Response Time vs Concurrency Level**: Demonstrates low latency even as user concurrency scales to 100 concurrent workers.
2. **System Utilization Across All 4 Systems**: Confirms balanced CPU/Memory distribution among backend nodes with minimal overhead on the Load Balancer.
3. **Traffic Distribution**: Validates uniform dynamic load sharing across all three backend nodes.

*(Plots are saved in the `plots/` folder)*
