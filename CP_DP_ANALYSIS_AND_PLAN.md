# 🔍 CP/DP Architecture Analysis & Implementation Plan

## **📋 Current CP/DP Architecture Analysis**

### **✅ What's Currently Implemented**

#### **Control Plane (CP) Mode**
- **Database Access**: Direct database access with full Admin API
- **Admin API**: Full read/write Admin API (HTTP + HTTPS + mTLS)
- **gRPC Server**: Exposes config sync service on port 50051
- **JWT Authentication**: Uses `FERRUM_CP_GRPC_JWT_SECRET` for DP authentication
- **Database Polling**: Polls DB every 30 seconds, broadcasts changes to DPs
- **Config Broadcasting**: Real-time config updates via gRPC streams

#### **Data Plane (DP) Mode**
- **No Admin API**: No admin endpoints (proxy-only)
- **gRPC Client**: Connects to CP for config sync
- **JWT Authentication**: Uses `FERRUM_DP_GRPC_AUTH_TOKEN` to authenticate to CP
- **Proxy Listeners**: HTTP/HTTPS proxy listeners for client traffic
- **Config Updates**: Receives real-time updates from CP
- **Reconnection Logic**: Auto-reconnects with 5-second retry interval

#### **Current Communication Flow**
```
┌─────────────────┐    gRPC (JWT)    ┌─────────────────┐
│   Control Plane │◄──────────────────▶│   Data Plane    │
│                 │                    │                 │
│ • Database     │                    │ • Proxy Only   │
│ • Admin API    │                    │ • No Admin API │
│ • gRPC Server  │                    │ • gRPC Client  │
└─────────────────┘                    └─────────────────┘
         ▲                                    ▲
         │                                    │
    Database Updates                    Config Sync
```

## **🚨 Issues & Missing Features**

### **1. Admin API Access in DP Mode**
**Problem**: DP mode has NO admin API access
- Cannot view current configuration
- Cannot check status of DP nodes
- Cannot manage consumers or plugins
- No operational visibility

### **2. Read-Only Mode Missing**
**Problem**: No read-only mode for admin API
- CP mode exposes full read/write admin API
- Should have read-only mode when serving DPs
- Security risk: Full admin access on all CP nodes

### **3. Authentication Security**
**Current**: Simple JWT token authentication
- Static token in environment variables
- No certificate-based authentication
- No mutual TLS between CP/DP

### **4. No Operational Separation**
**Problem**: CP and DP modes are completely separate
- Cannot run CP + DP in same process
- No hybrid deployment options
- No graceful mode transitions

## **🎯 Implementation Plan**

### **Phase 1: Admin API Read-Only Mode**

#### **1.1 Add Read-Only Flag to AdminState**
```rust
#[derive(Clone)]
pub struct AdminState {
    pub db: Option<Arc<DatabaseStore>>,
    pub jwt_manager: JwtManager,
    pub proxy_state: Option<ProxyState>,
    pub mode: String,
    pub read_only: bool,  // NEW: Read-only mode flag
}
```

#### **1.2 Environment Variable for Read-Only Mode**
```bash
# Environment variable for read-only admin API
FERRUM_ADMIN_READ_ONLY="true"  # Default: false
```

#### **1.3 Update Admin Handlers for Read-Only Mode**
```rust
// Modify handlers to check read_only flag
async fn handle_create_proxy(state: &AdminState, body: &[u8]) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"})
        ));
    }
    // ... existing create logic
}
```

#### **1.4 Read-Only Mode Handlers**
**Read-Only Operations (ALLOWED)**:
- `GET /proxies` - List all proxies
- `GET /proxies/{id}` - Get specific proxy
- `GET /consumers` - List all consumers
- `GET /consumers/{id}` - Get specific consumer
- `GET /plugins` - List plugin types
- `GET /plugins/config` - List plugin configs
- `GET /plugins/config/{id}` - Get specific plugin config
- `GET /health` - Health check
- `GET /admin/metrics` - Status metrics

**Write Operations (BLOCKED)**:
- `POST /proxies` - Create proxy
- `PUT /proxies/{id}` - Update proxy
- `DELETE /proxies/{id}` - Delete proxy
- `POST /consumers` - Create consumer
- `PUT /consumers/{id}` - Update consumer
- `DELETE /consumers/{id}` - Delete consumer
- `POST /plugins/config` - Create plugin config
- `PUT /plugins/config/{id}` - Update plugin config
- `DELETE /plugins/config/{id}` - Delete plugin config

### **Phase 2: Admin API in Data Plane Mode**

#### **2.1 Add Admin API to DP Mode**
```rust
// In data_plane.rs - Add admin API listeners
let admin_state = AdminState {
    db: None,  // DP has no direct DB access
    jwt_manager: create_jwt_manager_from_env()?,
    proxy_state: Some(proxy_state.clone()),
    mode: "dp".into(),
    read_only: true,  // DP admin API is always read-only
};
```

#### **2.2 DP Admin API Configuration**
```bash
# DP mode admin API (read-only)
FERRUM_ADMIN_HTTP_PORT="9000"        # Admin HTTP port
FERRUM_ADMIN_HTTPS_PORT="9443"       # Admin HTTPS port
FERRUM_ADMIN_READ_ONLY="true"          # Always read-only in DP mode
FERRUM_ADMIN_TLS_CERT_PATH="..."       # Optional admin TLS
FERRUM_ADMIN_TLS_KEY_PATH="..."       # Optional admin TLS
```

#### **2.3 DP Admin API Features**
**Read-Only Admin API in DP Mode**:
- View current configuration from CP
- Check proxy status and health
- View consumer configurations
- Monitor plugin settings
- Access operational metrics
- Debug configuration issues

**Limitations**:
- Cannot modify configuration (read-only)
- Configuration changes must go through CP
- No direct database access

### **Phase 3: Enhanced CP/DP Security**

#### **3.1 mTLS Authentication Between CP/DP**
```bash
# CP mTLS certificate for DP authentication
FERRUM_CP_TLS_CERT_PATH="/etc/ssl/cp-server.crt"
FERRUM_CP_TLS_KEY_PATH="/etc/ssl/cp-server.key"

# DP mTLS certificate for CP authentication
FERRUM_DP_TLS_CERT_PATH="/etc/ssl/dp-client.crt"
FERRUM_DP_TLS_KEY_PATH="/etc/ssl/dp-client.key"

# CP CA bundle for DP client verification
FERRUM_CP_CLIENT_CA_BUNDLE_PATH="/etc/ssl/dp-ca.pem"
```

#### **3.2 Enhanced gRPC with mTLS**
```rust
// In cp_server.rs - Add mTLS support
pub struct CpGrpcServer {
    config: Arc<ArcSwap<GatewayConfig>>,
    jwt_secret: String,
    update_tx: broadcast::Sender<ConfigUpdate>,
    tls_config: Option<Arc<ServerConfig>>,  // NEW: mTLS support
}

impl CpGrpcServer {
    pub fn new_with_mtls(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        tls_config: Option<Arc<ServerConfig>>,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        // ... existing logic + TLS support
    }
}
```

#### **3.3 Alternative: WebSocket with mTLS**
```rust
// WebSocket-based CP/DP communication
pub struct CpWebSocketServer {
    config: Arc<ArcSwap<GatewayConfig>>,
    update_tx: broadcast::Sender<ConfigUpdate>,
    tls_config: Option<Arc<ServerConfig>>,
}

// DP WebSocket client with mTLS
pub async fn start_dp_websocket_client(
    cp_url: String,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
    ca_bundle_path: Option<&str>,
    proxy_state: ProxyState,
) {
    // WebSocket connection with mTLS authentication
}
```

### **Phase 4: Testing & Validation**

#### **4.1 CP/DP Integration Tests**
```rust
#[tokio::test]
async fn test_cp_dp_config_sync() {
    // Start CP in background
    // Start DP in background
    // Verify config sync works
    // Test read-only admin API in DP
}

#[tokio::test]
async fn test_cp_dp_mtls_authentication() {
    // Test mTLS between CP and DP
    // Verify certificate validation
    // Test connection rejection with invalid certs
}
```

#### **4.2 Read-Only Mode Tests**
```rust
#[test]
fn test_admin_read_only_mode() {
    // Test read-only operations work
    // Test write operations are blocked
    // Verify proper error responses
}
```

## **🏗️ Final Architecture**

### **Enhanced CP/DP Architecture**
```
┌─────────────────┐    mTLS/gRPC     ┌─────────────────┐
│   Control Plane │◄──────────────────▶│   Data Plane    │
│                 │                    │                 │
│ • Database     │                    │ • Proxy Only   │
│ • Admin API    │                    │ • Read-Only    │
│ • gRPC/mTLS    │                    │ • gRPC/mTLS    │
│ • WebSocket     │                    │ • Admin API     │
└─────────────────┘                    └─────────────────┘
         ▲                                    ▲
         │                                    │
    Database Updates                    Config Sync
                                         ▲
                                         │
                                  Read-Only Admin
```

### **Deployment Options**

#### **Option 1: Separate CP/DP Nodes**
- CP node: Full admin + database + gRPC server
- DP nodes: Proxy + read-only admin + gRPC client
- mTLS between CP/DP
- Most secure and scalable

#### **Option 2: Hybrid CP/DP Mode**
- Single process running both CP and DP
- Full admin API for management
- Proxy functionality for traffic
- Internal config sync (no gRPC)
- Good for small deployments

#### **Option 3: WebSocket-Based CP/DP**
- CP: WebSocket server + admin API
- DP: WebSocket client + proxy + read-only admin
- mTLS WebSocket connections
- Firewall-friendly alternative to gRPC

## **🎯 Implementation Priority**

### **High Priority (Core Functionality)**
1. ✅ **Admin API Read-Only Mode** - Essential for DP admin access
2. ✅ **Admin API in DP Mode** - Basic operational visibility
3. ✅ **Environment Variables** - Configuration for new features

### **Medium Priority (Security Enhancement)**
4. 🔄 **CP/DP mTLS Authentication** - Enhanced security
5. 🔄 **WebSocket Alternative** - Firewall-friendly option
6. 🔄 **Hybrid Mode** - Single-process deployment

### **Low Priority (Advanced Features)**
7. 📋 **Enhanced Metrics** - CP/DP operational metrics
8. 📋 **Configuration Validation** - Pre-sync validation
9. 📋 **Graceful Transitions** - Mode switching without restart

## **🧪 Test Coverage**

### **New Test Files Needed**
- `tests/cp_dp_integration_tests.rs` - CP/DP communication tests
- `tests/admin_read_only_tests.rs` - Read-only admin API tests
- `tests/cp_dp_mtls_tests.rs` - mTLS authentication tests
- `tests/hybrid_mode_tests.rs` - Hybrid CP/DP mode tests

This plan provides a complete roadmap to make CP/DP architecture production-ready with proper security and operational visibility!
