# Distributed Secure Group Chat & Dynamic Performance-Based Load Balancer

A high-performance, fault-tolerant, distributed group chat system featuring a custom Go-based dynamic load balancer, decentralized peer-to-peer backend replication, sub-millisecond in-memory caching, cryptographic security (AES-256-GCM + Ed25519), and high-throughput persistence.

---

## 1. System Architecture

```
                      +-----------------------------+
                      |   Client / Load Generator   |
                      +--------------+--------------+
                                     | (External Port 6245)
                                     v
                        +------------------------+
                        |        System 1        |
                        | Dynamic Load Balancer  |  (:6000 -> :6245)
                        | (Go Reverse Proxy)     |
                        +-----------+------------+
                                    |
          +-------------------------+-------------------------+
          |                         |                         |
          v (Port 5246)             v (Port 5247)             v (Port 5248)
+-------------------+     +-------------------+     +-------------------+
|     System 2      |     |     System 3      |     |     System 4      |
| Backend Server 1  |<--->| Backend Server 2  |<--->| Backend Server 3  |
| (:5000)           |     | (:5000)           |     | (:5000)           |
| Local SQLite WAL  |     | Local SQLite WAL  |     | Local SQLite WAL  |
+-------------------+     +-------------------+     +-------------------+
          ^                         ^                         ^
          +=========================+=========================+
                     Decentralized Peer Replication (/sync)
                (Dedicated per-peer queues + 10 workers each)
```

---

## 2. Key Features & Real-World Optimizations

### Dynamic Performance-Based Load Balancer (`lb.go`)
- **Written in Go**: Extremely lightweight reverse proxy designed for maximum concurrency and sub-millisecond forwarding.
- **Dynamic Real-Time Scoring**:
  $$\text{Score} = (\text{ActiveRequests} \times 200) + (\text{CPULoad} \times 3) + \text{RecentLatencyMs}$$
- **Latency Smoothing**: Implements an Exponentially Weighted Moving Average (EWMA: $70\%$ historical + $30\%$ current) to prevent routing oscillation.
- **Active Health Monitoring**: Polls each backend's `/health` endpoint every 500ms to monitor CPU load and active connection counts.
- **Failover & Degradation Resilience**: If all backends are temporarily flagged as unhealthy, the proxy automatically fails over to the node with the lowest combined active requests and error count instead of dropping requests.
- **Connection Tuning for High Concurrency**: Injects `Connection: close` and sets `DisableKeepAlives: true` on the HTTP transport to eliminate unexpected EOF / socket reset errors under high-concurrency bursts against Werkzeug.

### Decentralized Peer-to-Peer Replication (`server.py`)
- **Zero Single Point of Failure (SPOF)**: Eliminates central database bottlenecks. Every backend maintains its own local SQLite storage and replicates incoming messages directly to all peers via `POST /sync`.
- **Dedicated Per-Peer Queues (`peer_queues`)**: Each remote peer node has an independent in-memory queue (`maxsize=100,000`) and 10 dedicated worker threads (20 replication workers per node).
- **Contention-Free Parallelism**: A slow or transiently failing peer never blocks or degrades replication to other healthy peers.
- **Automatic Retry with Backoff**: Unsuccessful sync requests are retried up to 3 times with exponential backoff.

### High-Throughput Storage & Deduplication
- **$O(1)$ In-Memory Deduplication**: Maintains an atomic `seen_message_ids` set to instantly reject duplicate messages caused by retries or network replays.
- **Asynchronous Batch Persistence**: Incoming messages are queued into `db_queue` and flushed in batches (up to 50 records) by a dedicated background thread (`db_writer_worker`).
- **SQLite Performance Tuning**: Uses Write-Ahead Logging (`PRAGMA journal_mode=WAL;`), asynchronous disk commits (`PRAGMA synchronous=OFF;`), and memory temp storage (`PRAGMA temp_store=MEMORY;`).
- **Zero Thread-Spawning Overhead**: All disk writes and peer synchronizations operate on pre-warmed daemon thread pools rather than spawning new threads per request.

### Fast Feed Retrieval & Memory Protection
- **Instant In-Memory Feed (< 2ms)**: The `/feed` endpoint returns all decrypted and verified messages directly from memory (`feed_cache`).
- **Time-Throttled JSON Feed Serialization**: Caches the pre-serialized JSON feed response with a 2-second throttle. Under massive concurrency (e.g., 1000 concurrent `/feed` reads), backends reuse the pre-encoded byte buffer, permanently eliminating CPU spikes, RAM ballooning, and Linux OOM killer crashes.

### End-to-End Cryptographic Security
- **AES-256-GCM Encryption**: Messages are encrypted using AES-256-GCM with unique 12-byte initialization vectors (nonces) for confidentiality and integrity.
- **Ed25519 Digital Signatures**: Every message is digitally signed by the sender, providing authenticity and non-repudiation.
- **Deterministic Multi-Node Key Derivation**: User keys and shared room keys are derived deterministically using SHA-256 HKDF-style key expansion from `SECRET_KEY`. Any backend can verify signatures and decrypt feeds with zero network key-exchange overhead and zero disk bottlenecks.

### Resilient API Schema Parsing
- **Fault-Tolerant `/message` Route**: Transparently parses and normalizes diverse payload schemas:
  - Formats: JSON dict, JSON list, form-urlencoded, query parameters, or raw plain text.
  - User identifiers: `client-name`, `client_name`, `sender`, `username`, `user`, `name`, `author`.
  - Message bodies: `msg`, `message`, `content`, `text`, `body`, `payload`, `data`.
  - Unique ID assignment: Automatically generates a deterministic UUID if none is supplied by the client.

---

## 3. Network Topology & Lab Port Configuration

All nodes reside on the local lab network (`10.1.75.79`):

| Node / Role | System | Internal Port | Mapped / External Port | Description |
|---|---|---|---|---|
| **Load Balancer** | System 1 (`stu42_sys1`) | `6000` | `6245` | Go Dynamic Reverse Proxy |
| **Backend 1** | System 2 (`stu42_sys2`) | `5000` | `5246` | Flask Backend Node 1 |
| **Backend 2** | System 3 (`stu42_sys3`) | `5000` | `5247` | Flask Backend Node 2 |
| **Backend 3** | System 4 (`stu42_sys4`) | `5000` | `5248` | Flask Backend Node 3 |

---

## 4. Deployment Instructions

### Prerequisites
Install Python dependencies on each backend node:
```bash
pip install -r requirements.txt
```

### 1. System 1 (`stu42_sys1` — Dynamic Load Balancer)
```bash
cd ~/new_load_balancer

# Start Dynamic Go Load Balancer on port 6000:
go run lb.go -backends="http://10.1.75.79:5246,http://10.1.75.79:5247,http://10.1.75.79:5248" -port=6000 -threshold=8
```

### 2. System 2 (`stu42_sys2` — Backend Node 1)
```bash
cd ~/group_chat_load_balancer
python3 server.py
```

### 3. System 3 (`stu42_sys3` — Backend Node 2)
```bash
cd ~/group_chat_load_balancer
python3 server.py
```

### 4. System 4 (`stu42_sys4` — Backend Node 3)
```bash
cd ~/group_chat_load_balancer
python3 server.py
```

---

## 5. Required HTTP Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/message` | Accepts new message, encrypts (AES-GCM), signs (Ed25519), persists, and queues peer replication. |
| `GET` | `/feed` | Returns verified, decrypted chat history from high-speed in-memory cache (< 2ms). |
| `GET` | `/health` | Returns real-time metrics (`cpu_percent`, `memory_percent`, `active_requests`, `stored_messages`). |
| `POST` | `/sync` | Internal peer-to-peer replication endpoint between backend nodes. |

---

## 6. Benchmarking & Evaluation

The repository includes a custom multi-threaded benchmarking tool (`load_generator.py`) capable of generating variable loads, validating data consistency, and producing evaluation plots.

```bash
# Run benchmark with 15 concurrent users, 30 messages each:
python3 load_generator.py --url http://10.1.75.79:6245 --users 15 --messages 30
```

### Evaluation Plots Generated
Plots are saved automatically to the `plots/` directory:
- `plots/latency_distribution.png`: Latency percentiles ($p50$, $p90$, $p95$, $p99$).
- `plots/throughput_vs_concurrency.png`: Requests/sec across varying levels of concurrency.
- `plots/system_utilization.png`: Real-time CPU and Memory utilization across all 4 systems.
- `plots/response_time_timeline.png`: End-to-end response latency over the duration of the test.
