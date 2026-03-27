# Features — Ferrum Gateway

A comprehensive feature list for Ferrum Gateway.

## Protocol Support

- **HTTP/1.1** with keep-alive connection pooling
- **HTTP/2** via ALPN negotiation on TLS connections
- **HTTP/3** (QUIC) on the same port as HTTPS with configurable idle timeout and max streams
- **WebSocket** (`ws`/`wss`) with transparent upgrade handling
- **gRPC** (`grpc`/`grpcs`) with HTTP/2 trailer support and full plugin compatibility
- **TCP** stream proxying with TLS termination and origination
- **UDP** datagram proxying with DTLS support (frontend termination + backend origination)

## Operating Modes

- **Database** — single-instance with PostgreSQL, MySQL, or SQLite backend
- **File** — single-instance with YAML/JSON config, SIGHUP reload
- **Control Plane (CP)** — centralized config authority, gRPC distribution to DPs
- **Data Plane (DP)** — horizontally scalable traffic processing nodes

## Routing

- Longest prefix match on `listen_path` with unique path enforcement
- Host-based routing with exact and wildcard prefix support (`*.example.com`)
- Pre-sorted route table with bounded O(1) path cache, rebuilt atomically on config changes
- Configurable path stripping and backend path prefixing

## Load Balancing

- Five algorithms: round robin, weighted round robin, least connections, consistent hashing, random
- Active health checks (HTTP, TCP SYN, UDP probes) with configurable thresholds
- Passive health monitoring with automatic failover
- Circuit breaker (Closed/Open/Half-Open) preventing cascading failures
- Retry logic with fixed and exponential backoff strategies

## Service Discovery

Ferrum supports dynamic upstream target discovery through three providers, configured via the `service_discovery` block on an upstream.

### Providers

- **DNS-SD** — discovers targets via DNS SRV record lookups. Suitable for environments using mDNS or service-aware DNS infrastructure. Configurable service name and poll interval.
- **Kubernetes** — queries the Kubernetes API for endpoint addresses backing a named Service. Supports namespace scoping and named port selection. Requires in-cluster credentials or a configured kubeconfig.
- **Consul** — queries a Consul agent or server for healthy service instances. Supports datacenter selection and ACL token authentication.

### Behavior

- **Background polling** — each provider polls on a configurable interval (`poll_interval_seconds`), updating the upstream's target list without blocking request traffic.
- **Static + dynamic target merging** — statically defined `targets` on an upstream are preserved and merged with dynamically discovered targets. This allows fallback entries that are always present.
- **Resilience** — if a provider becomes unreachable (DNS timeout, Kubernetes API error, Consul agent down), the upstream retains its last-known target list and continues routing normally. A warning is logged on each failed poll. Normal updates resume automatically when the provider recovers.

## Plugin System

- 20 built-in plugins with lifecycle hooks (request received, authenticate, authorize, before proxy, after proxy, log)
- Priority-ordered execution with protocol-aware filtering (HTTP, gRPC, WebSocket, TCP, UDP)
- Global and per-proxy scoping with same-type override semantics
- Multi-authentication mode with first-match consumer identification

### Authentication Plugins

- **JWT** (HS256) — bearer token with configurable claim field
- **API Key** — header or query parameter lookup
- **Basic Auth** — bcrypt or HMAC-SHA256 password verification
- **HMAC** — request signature verification
- **OAuth2** — introspection and JWKS validation modes

### Authorization & Security Plugins

- **Access Control** — IP/CIDR and consumer-based allow/deny lists
- **IP Restriction** — standalone IP/CIDR filtering
- **Rate Limiting** — per-IP or per-consumer with configurable windows and optional header exposure
- **Bot Detection** — User-Agent pattern blocking with allow-list support
- **CORS** — preflight handling with origin, method, and header validation
- **Body Validator** — JSON Schema and XML validation

### Transform Plugins

- **Request Transformer** — add, remove, or update headers and query parameters
- **Response Transformer** — modify response headers
- **Request Termination** — return static responses without proxying

### Observability Plugins

- **Stdout Logging** — JSON transaction summaries
- **HTTP Logging** — batched delivery to external endpoints with retry
- **Transaction Debugger** — verbose request/response logging with header redaction
- **Correlation ID** — UUID generation and propagation
- **Prometheus Metrics** — exposition format endpoint
- **OpenTelemetry Tracing** — OTLP integration

## Connection Pooling

- Lock-free connection reuse with per-proxy pool keys
- Global defaults with per-proxy overrides (max idle, idle timeout, keep-alive, HTTP/2)
- HTTP/2 multiplexing via ALPN negotiation
- TCP and HTTP/2 keep-alive with configurable intervals

## TLS & Security

- Frontend TLS termination on proxy and admin listeners
- Frontend mTLS with client certificate verification
- Backend mTLS with per-proxy certificate configuration
- DTLS frontend termination and backend origination (ECDSA P-256 / Ed25519)
- Configurable cipher suites, key exchange groups, and protocol versions
- Database TLS/SSL with PostgreSQL and MySQL support

## DNS Caching

- In-memory async cache with startup warmup (backends, upstreams, plugin endpoints)
- Background refresh at 75% TTL with stale-while-revalidate
- Per-proxy TTL overrides and static hostname overrides
- Shared resolver for all outbound HTTP clients including plugins

## Configuration & Admin

- Admin REST API with JWT authentication and read-only mode
- Full CRUD for proxies, consumers, plugin configs, and upstreams
- Batch operations and full config backup/restore
- Zero-downtime config reload via DB polling, SIGHUP, or CP push
- Atomic config swap via ArcSwap (no partial config visible to requests)
- Incremental database polling with indexed `updated_at` queries

## Resilience

- In-memory config cache survives source outages (DB, file, gRPC)
- Startup failover with externally provisioned backup config (`FERRUM_DB_CONFIG_BACKUP_PATH`)
- Graceful shutdown with active request draining (SIGTERM/SIGINT)
- Client observability headers (`X-Gateway-Error`, `X-Gateway-Upstream-Status`)

## Deployment

- Single binary, mode selected via environment variable
- Docker multi-stage build with health check endpoint
- Docker Compose profiles for SQLite, PostgreSQL, and CP/DP topologies
- CI pipeline: unit tests, functional tests, lint, performance regression
