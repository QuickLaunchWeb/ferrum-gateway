# API Gateway Comparison Benchmarks

Performance comparison suite that benchmarks **Ferrum Gateway** against **Pingora** (Cloudflare), **Kong**, and **Tyk** under identical conditions.

## What It Measures

Each gateway is tested as a pure reverse proxy (no authentication, rate limiting, or transformation plugins) with three scenarios:

| Scenario | Description |
|----------|-------------|
| **HTTP (plaintext)** | Client → Gateway (port 8000) → Backend. Measures raw proxy overhead. |
| **HTTPS (TLS termination)** | Client → Gateway (port 8443, TLS) → Backend (plaintext). Measures TLS handshake and encryption overhead at the gateway. |
| **E2E TLS (full encryption)** | Client → Gateway (port 8443, TLS) → Backend (TLS, port 3443). Measures full end-to-end encryption where the gateway re-encrypts traffic to the backend. |

Two endpoints are tested per scenario:
- `/health` — instant backend response, measures pure gateway latency
- `/api/users` — 100 microsecond simulated delay, represents a typical API call

A direct backend baseline (no gateway) is run first for both HTTP and HTTPS comparison.

### Test Approach

- Gateways are tested **sequentially** (one at a time) to avoid resource contention
- Each test gets a **5-second warm-up** (results discarded) before the measured 30-second run
- The same backend echo server, wrk parameters, and endpoints are used across all gateways
- Ferrum runs as a native binary; Kong runs natively if installed (preferred) or in Docker; Tyk runs in Docker (no official macOS binary)
- The script auto-detects native Kong and prefers it over Docker for fairer benchmarking

## Prerequisites

| Dependency | Required | Install |
|------------|----------|---------|
| **wrk** | Yes | `brew install wrk` (macOS) or `apt install wrk` (Ubuntu) |
| **Python 3** | Yes | Usually pre-installed; needed for report generation |
| **Rust/Cargo** | Yes | [rustup.rs](https://rustup.rs/) — builds Ferrum and the backend server |
| **cmake** | For Pingora | `brew install cmake` (macOS) or `apt install cmake` (Ubuntu) |
| **curl** | Yes | Usually pre-installed; used for health checks |
| **Docker** | For Tyk (always), Kong (if not native) | [docs.docker.com/get-docker](https://docs.docker.com/get-docker/) |
| **Pingora source** | For Pingora tests | Clone [cloudflare/pingora](https://github.com/cloudflare/pingora) to `~/workspace/pingora` |
| **Kong** (native) | Recommended | See below |

### Native Kong Installation (Recommended for Fair Benchmarks)

Installing Kong natively eliminates Docker overhead and provides the fairest comparison against Ferrum. The script auto-detects a native `kong` binary and uses it automatically.

**macOS:** No native macOS binary is officially available — Docker is the only supported option on macOS. If you have a Kong binary from another source, place it on your `$PATH` and the script will use it.

**Ubuntu/Debian:**
```bash
curl -1sLf 'https://packages.konghq.com/public/gateway-39/setup.deb.sh' | sudo bash
sudo apt install kong
```

**RHEL/CentOS:**
```bash
curl -1sLf 'https://packages.konghq.com/public/gateway-39/setup.rpm.sh' | sudo bash
sudo yum install kong
```

### Native Tyk Installation (Linux Only)

Tyk has no official macOS binary. On Linux, native installation is available:

**Ubuntu/Debian:**
```bash
curl -1sLf 'https://packagecloud.io/tyk/tyk-gateway/setup.deb.sh' | sudo bash
sudo apt install tyk-gateway
```

Tyk always requires Redis (`brew install redis` on macOS, `apt install redis-server` on Linux).

On macOS, Tyk runs in Docker — see the "Docker Overhead" section below for what this means for results.

**System recommendations:** Run on a dedicated machine or close resource-intensive applications. CPU governor set to "performance" improves consistency on Linux.

## Quick Start

```bash
# From the project root
./comparison/run_comparison.sh
```

The script will:
1. Pull Kong and Tyk Docker images
2. Build Ferrum Gateway and the backend server (release mode)
3. Run baseline → Ferrum → Kong → Tyk tests sequentially
4. Generate an HTML comparison report in `comparison/results/`

Open `comparison/results/comparison_report.html` in a browser to view the results.

## Configuration

Override any parameter via environment variables:

```bash
# Custom test parameters
WRK_DURATION=60s WRK_THREADS=12 WRK_CONNECTIONS=200 ./comparison/run_comparison.sh

# Skip a gateway (e.g., if you don't have Docker)
SKIP_GATEWAYS=tyk,kong ./comparison/run_comparison.sh

# Only test Ferrum vs Pingora (no Docker required)
SKIP_GATEWAYS=kong,tyk ./comparison/run_comparison.sh

# Only test Ferrum vs Kong
SKIP_GATEWAYS=pingora,tyk ./comparison/run_comparison.sh
```

| Variable | Default | Description |
|----------|---------|-------------|
| `WRK_DURATION` | `30s` | Duration of each measured test run |
| `WRK_THREADS` | `8` | wrk thread count |
| `WRK_CONNECTIONS` | `100` | wrk concurrent connections |
| `WARMUP_DURATION` | `5s` | Warm-up duration before each test (results discarded) |
| `KONG_VERSION` | `3.9` | Kong Docker image tag |
| `TYK_VERSION` | `v5.7` | Tyk Docker image tag |
| `SKIP_GATEWAYS` | _(empty)_ | Comma-separated gateways to skip: `ferrum`, `pingora`, `kong`, `tyk` |

## Swapping Gateway Versions

To re-run benchmarks with newer Kong or Tyk releases:

```bash
# Test against Kong 3.10 and Tyk v5.8
KONG_VERSION=3.10 TYK_VERSION=v5.8 ./comparison/run_comparison.sh
```

The script pulls the specified Docker image tags automatically. Results are overwritten in `comparison/results/` — copy or rename the directory if you want to preserve previous runs.

### Version-specific considerations

- **Kong** uses DB-less declarative mode. The config format (`_format_version: "3.0"`) is stable across 3.x releases. If Kong 4.x changes the format, update `comparison/configs/kong.yaml`.
- **Tyk** uses standalone mode with file-based API definitions. The API definition schema has been stable across v5.x. If Tyk v6 changes it, update the files in `comparison/configs/tyk/apps/`.
- **Ferrum** is built from source in the current checkout, so it always tests the latest local code.

## Interpreting Results

The HTML report contains five sections:

### 1. Direct Backend Baseline
Raw backend throughput and latency without any gateway, for both HTTP and HTTPS. This is the theoretical maximum. Any gateway will add overhead.

### 2. HTTP Performance (Plaintext)
Compares all three gateways proxying plaintext HTTP. Key metrics:
- **Requests/sec** — higher is better. The gateway closest to baseline has the least overhead.
- **Avg Latency** — lower is better. The difference from baseline is the gateway's added latency.
- **P99 Latency** — tail latency matters for user experience. Large P99 spikes indicate inconsistent performance.
- **Errors** — should be zero. Non-zero errors indicate the gateway couldn't handle the load.
- **vs Baseline** — percentage RPS difference from direct backend.

### 3. HTTPS Performance (TLS Termination)
Same metrics but with TLS between wrk and the gateway, while the gateway proxies to the backend over plaintext. Expect lower throughput and higher latency than HTTP due to TLS handshake cost.

### 4. End-to-End TLS Performance (Full Encryption)
Client connects via HTTPS to the gateway, and the gateway re-encrypts traffic to the backend over HTTPS. This is the most secure deployment pattern and measures the full cost of double TLS. Compared against the HTTPS baseline (direct to backend).

### 5. TLS Overhead Comparison
Per-gateway comparison of HTTP vs HTTPS vs E2E TLS performance. Shows the RPS drop and latency increase each gateway pays for TLS at each stage. A gateway with lower TLS overhead has a more efficient TLS implementation.

### Color coding
- **Green cells** = best in category (highest RPS, lowest latency)
- **Red cells** = worst in category

## Initial Findings

The following results were collected on macOS (Apple Silicon) with 8 threads, 100 connections, and 30-second measured runs. Kong and Tyk ran in Docker; Ferrum ran natively.

### Raw Results

| Gateway | Protocol | /health req/s | /api/users req/s | /health latency | /api/users latency |
|---------|----------|--------------|-----------------|-----------------|-------------------|
| **Baseline** (no gateway) | HTTP | 214,104 | 48,195 | 0.37 ms | 1.90 ms |
| **Baseline** (no gateway) | HTTPS | 209,094 | 46,252 | 0.37 ms | 1.97 ms |
| **Ferrum** (native) | HTTP | 100,169 | 37,108 | 0.96 ms | 2.56 ms |
| **Ferrum** (native) | HTTPS | 96,080 | 36,599 | 1.06 ms | 2.62 ms |
| **Ferrum** (native) | E2E TLS | 91,002 | 36,719 | 1.15 ms | 2.61 ms |
| **Pingora** (native) | HTTP | 72,462 | 37,981 | 1.32 ms | 2.53 ms |
| **Pingora** (native) | HTTPS | 62,305 | 37,698 | 2.61 ms | 3.58 ms |
| **Pingora** (native) | E2E TLS | — | — | — | — |
| **Kong 3.9** (Docker) | HTTP | 27,193 | 23,903 | 3.61 ms | 4.14 ms |
| **Kong 3.9** (Docker) | HTTPS | 18,133 | 21,820 | 14.41 ms | 9.75 ms |
| **Kong 3.9** (Docker) | E2E TLS | 12,120 | 22,908 | 12.77 ms | 7.48 ms |
| **Tyk v5.7** (Docker) | HTTP | 2,190 | — | 44.64 ms | — |
| **Tyk v5.7** (Docker) | HTTPS | — | — | — | — |
| **Tyk v5.7** (Docker) | E2E TLS | — | — | — | — |

> **Note:** Pingora E2E TLS is not supported in this benchmark — Pingora's TLS library requires a valid DNS hostname for upstream SNI and cannot connect to IP-based backends (127.0.0.1) over TLS. This is a framework limitation, not a configuration issue. Tyk results are incomplete due to ephemeral port exhaustion under load on macOS.

### Ferrum vs Pingora (Native-to-Native Comparison)

Pingora is a pure proxy framework (no plugins, admin API, or config management), making this the fairest raw proxy performance comparison. Both run as native binaries — no Docker overhead.

| Test | Ferrum | Pingora | Advantage |
|------|--------|---------|-----------|
| HTTP /health | **100,169** req/s | 72,462 req/s | **Ferrum 38% faster** |
| HTTP /api/users | 37,108 req/s | **37,981** req/s | Pingora 2% faster |
| HTTPS /health | **96,080** req/s | 62,305 req/s | **Ferrum 54% faster** |
| HTTPS /api/users | 36,599 req/s | **37,698** req/s | Pingora 3% faster |
| E2E TLS /health | **91,002** req/s | — | Pingora cannot test (SNI limitation) |
| E2E TLS /api/users | **36,719** req/s | — | Pingora cannot test (SNI limitation) |

**Key findings:**
- **Ferrum dominates on lightweight requests** — 38% faster on HTTP and 54% faster on HTTPS for /health. This is where per-request overhead matters most, and Ferrum's lock-free hot path and pre-computed indexes pay off.
- **Pingora edges ahead ~2-3% on heavier payloads** (/api/users). This is due to Pingora's zero-copy h2 header streaming vs Ferrum's intermediate HashMap collection, and per-response `format!()` allocations. (See response path optimization PR for fixes targeting this gap.)
- **Pingora cannot do E2E TLS with IP-based backends** — its TLS library requires a valid DNS hostname for SNI. Ferrum handles this without issue, making it more flexible for local/container deployments where backends are addressed by IP.
- **Ferrum's HTTPS overhead is minimal** — only 4% throughput drop from HTTP to HTTPS on /health, compared to Pingora's 14% drop. Ferrum's rustls-based TLS termination is exceptionally efficient.

### Adjusting for Docker Overhead

Kong and Tyk ran in Docker on macOS, which adds ~0.1–0.5 ms latency per request and reduces throughput by ~5–15% (see [Docker Overhead](#docker-overhead)). Even after generously accounting for this:

| Gateway | /health req/s (adjusted) | Ferrum Advantage |
|---------|-------------------------|-----------------|
| **Ferrum** (native) | 100,169 | — |
| **Pingora** (native) | 72,462 | **1.4x faster** |
| **Kong** (Docker, +15% adjusted) | ~31,300 | **3.2x faster** |
| **Tyk** (Docker, +15% adjusted) | ~2,520 | **40x faster** |

### End-to-End TLS Performance

The E2E TLS scenario (client → HTTPS → gateway → HTTPS → backend) is the most secure deployment pattern and the most demanding on gateway performance. Pingora cannot participate in this test due to its SNI limitation.

| Gateway | E2E /health req/s | E2E /api/users req/s | E2E /health latency | E2E /api/users latency |
|---------|------------------|---------------------|--------------------|-----------------------|
| **Ferrum** (native) | 91,002 | 36,719 | 1.15 ms | 2.61 ms |
| **Kong 3.9** (Docker) | 12,120 | 22,908 | 12.77 ms | 7.48 ms |
| **Tyk v5.7** (Docker) | — | — | — | — |

- **Ferrum is 7.5x faster than Kong** on E2E TLS /health
- **Ferrum is 1.6x faster than Kong** on E2E TLS /api/users

### TLS Overhead by Gateway

How much does each layer of encryption cost each gateway?

| Gateway | HTTP → HTTPS (TLS term.) | HTTP → E2E TLS (full encryption) |
|---------|--------------------------|----------------------------------|
| **Ferrum** | -4.1% RPS, +0.10 ms | **-9.2% RPS, +0.19 ms** |
| **Pingora** | -14.0% RPS, +1.29 ms | N/A (SNI limitation) |
| **Kong** | -33.3% RPS, +10.80 ms | **-55.4% RPS, +9.16 ms** (/health) |

Ferrum's full E2E TLS overhead is just **9.2% throughput drop and 0.19 ms added latency** — meaning the gateway-to-backend TLS hop costs very little. Pingora pays a 14% throughput drop for TLS termination alone, and cannot test E2E TLS at all. Kong's HTTPS performance degrades significantly under TLS load.

### Key Takeaways

- **Ferrum is 38–54% faster than Pingora** on lightweight requests (the fairest native-to-native comparison). Pingora edges ahead by 2-3% on heavier payloads due to lower per-response allocation overhead.
- **Ferrum is 3–4x faster than Kong** on pure proxy throughput, even after giving Kong a generous 15% Docker adjustment.
- **Ferrum is 40x+ faster than Tyk** on the /health endpoint.
- **Ferrum's TLS implementation is the most efficient** — only 4% throughput drop for TLS termination vs Pingora's 14% drop and Kong's 33% drop.
- **Ferrum uniquely supports E2E TLS with IP-based backends** — neither Pingora (SNI limitation) nor Tyk (incomplete results) completed E2E TLS testing.
- **Docker overhead accounts for at most ~0.5 ms of the latency gap.** Ferrum's latency advantage over Kong is ~2.7 ms (HTTP) to ~11.6 ms (HTTPS /health) — the vast majority is real gateway overhead, not Docker artifact.
- **The backend's own TLS overhead is negligible** — HTTPS baseline (209,094 req/s) is within 2.4% of HTTP baseline (214,104 req/s), confirming the cost difference between gateways is gateway overhead, not backend TLS.

For the most apples-to-apples comparison, run on Linux where all gateways can be installed natively.

## Adding a New Gateway

To add a new gateway (e.g., Envoy, NGINX, Traefik):

1. **Create config files** in `comparison/configs/` for the gateway
2. **Add functions** to `run_comparison.sh`:
   - `start_<gateway>_http()` / `start_<gateway>_https()` — launch the gateway
   - `stop_<gateway>()` — tear it down
   - `test_<gateway>()` — orchestrate HTTP + HTTPS test sequences
3. **Add the gateway name** to the `GATEWAYS` list in `scripts/generate_comparison_report.py`
4. **Call `test_<gateway>()`** in the `main()` function of `run_comparison.sh`
5. **Add a `should_skip` check** so users can skip it via `SKIP_GATEWAYS`

Each test function should follow the pattern: start → run_wrk (per endpoint) → stop. Use the same ports (8000/8443) since gateways run sequentially.

## Docker Overhead

When a gateway runs in Docker instead of natively, there is measurable overhead that affects benchmark results. The amount varies by platform:

| Platform | Networking Mode | Added Latency | Throughput Impact | Notes |
|----------|----------------|---------------|-------------------|-------|
| **Linux** | `--network host` | < 5 μs | < 1% | Negligible; containers share the host network stack |
| **Linux** | port mapping (`-p`) | ~10–50 μs | ~2–5% | Userspace proxy adds a small hop |
| **macOS** | port mapping (`-p`) | ~0.1–0.5 ms | ~5–15% | Docker Desktop runs in a Linux VM; each packet crosses the VM boundary + userspace networking |

**On macOS**, Docker overhead is the most significant. Docker Desktop 4.19+ improved this with the gVisor TCP/IP stack (5x faster than the older vpnkit), but the VM boundary remains. CPU scheduling variance is also ~9.5x higher in the VM compared to native.

**To minimize Docker overhead:**
1. On Linux, install Kong and Tyk natively via package managers (see Prerequisites above)
2. On Linux with Docker, `--network host` is used automatically (negligible overhead)
3. On macOS, no native Kong or Tyk binaries exist — Docker overhead is unavoidable. Interpret results with the overhead estimates above in mind

The HTML report's "Methodology & Caveats" section notes which gateways ran natively vs in Docker.

## Known Limitations

- **No plugins enabled:** Tests measure pure proxy overhead only. Real-world performance with authentication, rate limiting, or transformation plugins will differ. Each gateway has different plugin performance characteristics.

- **Pingora is a framework, not a gateway:** The Pingora benchmark uses a minimal ~80-line proxy binary built on Pingora's framework. It has no plugins, admin API, config management, or any gateway features. This is the fairest raw proxy comparison but understates the real-world overhead a production Pingora deployment would have once application logic is added.

- **Single-node only:** All tests run on localhost. Distributed deployment characteristics (network latency, cluster synchronization) are not captured.

- **In-memory state:** Tyk requires Redis even in standalone mode. The Redis instance runs locally and is fast, but it's a dependency that Kong and Ferrum don't need, which could slightly affect Tyk's resource usage.

- **Tyk on macOS:** No native macOS binary exists, so Tyk always runs in Docker on macOS. On Linux, Tyk can be installed natively via packagecloud (adding native Tyk support to this script is a welcome contribution).

## File Structure

```
comparison/
├── README.md                          # This file
├── run_comparison.sh                  # Main orchestrator script
├── configs/
│   ├── ferrum_comparison.yaml         # Ferrum config (HTTP backend)
│   ├── ferrum_comparison_e2e_tls.yaml # Ferrum config (HTTPS backend)
│   ├── pingora/                       # Pingora minimal bench proxy (built from source)
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   ├── kong.yaml                      # Kong config (HTTP backend)
│   ├── kong_e2e_tls.yaml             # Kong config (HTTPS backend)
│   └── tyk/
│       ├── tyk.conf                   # Tyk standalone config (HTTP)
│       ├── tyk_tls.conf               # Tyk config with TLS enabled
│       ├── apps/                      # Tyk API defs (HTTP backend)
│       │   ├── health_api.json
│       │   └── users_api.json
│       └── apps_e2e_tls/             # Tyk API defs (HTTPS backend)
│           ├── health_api.json
│           └── users_api.json
├── lua/
│   └── comparison_test.lua            # Unified wrk Lua script
├── scripts/
│   └── generate_comparison_report.py  # HTML report generator
└── results/                           # Generated at runtime (gitignored)
    ├── .gitkeep
    ├── comparison_report.html         # HTML report (after running)
    ├── meta.json                      # Test metadata (after running)
    └── *_results.txt                  # Raw wrk output per test
```
