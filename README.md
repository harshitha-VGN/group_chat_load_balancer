# Distributed Secure Group Chat & Dynamic Performance-Based Load Balancer

## Architecture Overview

```
                      +-----------------------------+
                      |   Client / Load Generator   |
                      +--------------+--------------+
                                     | (External Port 6245)
                                     v
                        +------------------------+
                        |      System 1          |
                        | Dynamic Load Balancer  |  (:6000 -> :6245)
                        | (Performance Switching)|
                        +-----------+------------+
                                    |
          +-------------------------+-------------------------+
          |                         |                         |
          v (Port 5246)             v (Port 5247)             v (Port 5248)
+-------------------+     +-------------------+     +-------------------+
|     System 2      |     |     System 3      |     |     System 4      |
| Backend Server 1  |     | Backend Server 2  |     | Backend Server 3  |
| (:5000)           |     | (:5000)           |     | (:5000)           |
+---------+---------+     +---------+---------+     +---------+---------+
          |                         |                         |
          +-------------------------+-------------------------+
                                    |  (Internal DB Sync)
                                    v
                        +------------------------+
                        |      System 1          |
                        |   Central DB Service   |  (:7000)
                        | (Deduplication + WAL)  |
                        +------------------------+
```

---

## Key Features

1. **Dynamic Performance-Based Load Balancing (`lb.go`)**:
   - Written in Go for ultra-high throughput and low latency.
   - Monitors active requests, CPU load, and response latency.
   - Dynamic Scoring Formula: `Score = (ActiveRequests * 100) + (CPULoad * 2) + RecentLatencyMs`.
   - Automatically diverts traffic when a backend's load exceeds the defined performance threshold ($T = 8$).
   - Active background health checks and automatic failover retries.

2. **Full Data Persistence & Zero Duplicates**:
   - `db_service.py` provides centralized, synchronized persistence across all 3 backend nodes.
   - Messages are stored in SQLite with Write-Ahead Logging (WAL) mode.
   - Idempotency & deduplication via unique `message_id` constraint prevents duplicate insertion during reconnections or retries.

3. **Cryptographic Security Intact**:
   - AES-256-GCM symmetric encryption for message privacy.
   - Ed25519 digital signatures per sender for authentication & non-repudiation.
   - Tamper-detection on `/feed` retrieval.

4. **Required API Routes**:
   - `POST /message`: Accepts `client-name` and `msg` (and optional `id`).
   - `GET /feed`: Returns all decrypted, verified messages.
   - `GET /health`: Returns system status and real-time load metrics.

---

## Deployment Instructions on Lab Systems

### On System 1 (`stu42_sys1` — Load Balancer & DB):
```bash
cd ~/new_load_balancer

# 1. Start Central DB Service in background on port 7000:
python3 db_service.py &

# 2. Start Dynamic Load Balancer on port 6000:
go run lb.go
```

### On System 2 (`stu42_sys2` — Backend 1):
```bash
cd ~/group_chat_load_balancer
python3 server.py
```

### On System 3 (`stu42_sys3` — Backend 2):
```bash
cd ~/group_chat_load_balancer
python3 server.py
```

### On System 4 (`stu42_sys4` — Backend 3):
```bash
cd ~/group_chat_load_balancer
python3 server.py
```

---

## Running the Load Generator & Generating Report Plots

From your Mac terminal:
```bash
# Run benchmark with 15 concurrent users, 30 messages each:
python3 load_generator.py --url http://10.1.75.79:6245 --users 15 --messages 30
```

Plots will be automatically saved in the `plots/` directory:
- `plots/response_time_vs_concurrency.png`
- `plots/system_utilization_all_4_systems.png`
- `plots/dynamic_lb_traffic_distribution.png`

---

## Leaderboard Submission

- **Roll ID**: Your Roll Number
- **Load Balancer URL**: `http://10.1.75.79:6245`
