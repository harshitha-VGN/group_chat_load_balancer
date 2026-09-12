# Distributed Secure Group Chat & Dynamic Performance-Based Load Balancer

## Architecture Overview

```
                      +-----------------------------+
                      |   Client / Load Generator   |
                      +--------------+--------------+
                                     |
                                     v
                        +------------------------+
                        |      System 1          |
                        | Dynamic Load Balancer  |  (:8080)
                        | (Performance Switching)|
                        +-----------+------------+
                                    |
          +-------------------------+-------------------------+
          |                         |                         |
          v                         v                         v
+-------------------+     +-------------------+     +-------------------+
|     System 2      |     |     System 3      |     |     System 4      |
| Backend Node 1    |     | Backend Node 2    |     | Backend Node 3    |
| (:5000)           |     | (:5000)           |     | (:5000)           |
+---------+---------+     +---------+---------+     +---------+---------+
          |                         |                         |
          +-------------------------+-------------------------+
                                    |  (Shared Persistence)
                                    v
                        +------------------------+
                        |      System 1          |
                        |   Central DB Service   |  (:5001)
                        | (Deduplication + WAL)  |
                        +------------------------+
```

---

## Key Features

1. **Dynamic Performance-Based Load Balancing (`lb.go`)**:
   - Written in Go for ultra-high throughput and low latency.
   - Monitors active requests, CPU load, and response latency.
   - Automatically diverts traffic when a backend's load exceeds the defined performance threshold.
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

### On System 1 (`stu42_sys1`):
```bash
cd ~/load-balancer   # or your project directory
# Start Central DB and Load Balancer
./start_sys1.sh
```
*Note: Make sure `BACKENDS` in `start_sys1.sh` points to the IPs/hostnames of System 2, 3, and 4.*

### On System 2 (`stu42_sys2`):
```bash
cd ~/Group-Chat
./start_backend.sh <SYS1_IP> 5000
```

### On System 3 (`stu42_sys3`):
```bash
cd ~/Group-Chat
./start_backend.sh <SYS1_IP> 5000
```

### On System 4 (`stu42_sys4`):
```bash
cd ~/Group-Chat
./start_backend.sh <SYS1_IP> 5000
```

---

## Running the Load Generator & Generating Report Plots

In your local virtual environment:
```bash
# Run benchmark with 20 concurrent users, 50 messages each:
python3 load_generator.py --url http://<SYS1_IP>:8080 --users 20 --messages 50

# Generate plots for the report:
python3 load_generator.py --generate-plots
```
Plots will be saved in the `plots/` directory:
- `plots/response_time_vs_concurrency.png`
- `plots/system_utilization_all_4_systems.png`
- `plots/dynamic_lb_traffic_distribution.png`
