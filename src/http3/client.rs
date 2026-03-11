//! HTTP/3 client for proxying requests to HTTP/3 backends

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::Request;
use quinn::crypto::rustls::QuicClientConfig;
use tracing::debug;

use crate::config::types::Proxy;

/// HTTP/3 client for connecting to backend services over QUIC.
pub struct Http3Client {
    endpoint: quinn::Endpoint,
}

impl Http3Client {
    /// Create a new HTTP/3 client with the given TLS configuration.
    pub fn new(tls_config: Arc<rustls::ClientConfig>) -> Result<Self, anyhow::Error> {
        // Bind to any available local UDP port
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;

        let mut client_tls_config = (*tls_config).clone();
        client_tls_config.alpn_protocols = vec![b"h3".to_vec()];

        let quic_client_config = QuicClientConfig::try_from(client_tls_config)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC client config: {}", e))?;

        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .map_err(|e| anyhow::anyhow!("Invalid timeout: {}", e))?,
        ));

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport));

        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    /// Send an HTTP/3 request to the specified backend.
    pub async fn request(
        &self,
        proxy: &Proxy,
        method: &str,
        path: &str,
        headers: &std::collections::HashMap<String, String>,
        body: Vec<u8>,
        resolved_addr: Option<SocketAddr>,
    ) -> Result<(u16, Vec<u8>, std::collections::HashMap<String, String>), anyhow::Error> {
        let addr = match resolved_addr {
            Some(a) => a,
            None => {
                let ip: std::net::IpAddr = proxy
                    .backend_host
                    .parse()
                    .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
                SocketAddr::new(ip, proxy.backend_port)
            }
        };

        let server_name = proxy.backend_host.clone();

        debug!(
            "HTTP/3 client connecting to {}:{} ({})",
            server_name, proxy.backend_port, addr
        );

        // Establish QUIC connection
        let connection = self
            .endpoint
            .connect(addr, &server_name)?
            .await
            .map_err(|e| anyhow::anyhow!("QUIC connection failed: {}", e))?;

        // Create HTTP/3 connection
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;

        // Drive the connection in background
        tokio::spawn(async move {
            let _err = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
            debug!("HTTP/3 connection driver closed");
        });

        // Build the request
        let uri = format!(
            "https://{}:{}{}",
            proxy.backend_host, proxy.backend_port, path
        );

        let req_method = match method {
            "GET" => http::Method::GET,
            "POST" => http::Method::POST,
            "PUT" => http::Method::PUT,
            "DELETE" => http::Method::DELETE,
            "PATCH" => http::Method::PATCH,
            "HEAD" => http::Method::HEAD,
            "OPTIONS" => http::Method::OPTIONS,
            _ => http::Method::GET,
        };

        let mut req_builder = Request::builder().method(req_method).uri(&uri);

        for (k, v) in headers {
            match k.as_str() {
                "host" | ":authority" => {
                    if proxy.preserve_host_header {
                        req_builder = req_builder.header("host", v.as_str());
                    } else {
                        req_builder = req_builder.header("host", &proxy.backend_host);
                    }
                }
                "connection" | "transfer-encoding" => continue,
                k if k.starts_with(':') => continue,
                _ => {
                    req_builder = req_builder.header(k, v.as_str());
                }
            }
        }

        let req = req_builder
            .body(())
            .map_err(|e| anyhow::anyhow!("Failed to build request: {}", e))?;

        // Send request
        let mut stream = send_request.send_request(req).await?;

        // Send body if present
        if !body.is_empty() {
            stream.send_data(Bytes::from(body)).await?;
        }
        stream.finish().await?;

        // Receive response
        let resp = stream.recv_response().await?;
        let status = resp.status().as_u16();

        let mut resp_headers = std::collections::HashMap::new();
        for (k, v) in resp.headers() {
            if let Ok(vs) = v.to_str() {
                resp_headers.insert(k.as_str().to_string(), vs.to_string());
            }
        }

        // Collect response body
        let mut resp_body = Vec::new();
        while let Some(chunk) = stream.recv_data().await? {
            resp_body.extend_from_slice(chunk.chunk());
        }

        Ok((status, resp_body, resp_headers))
    }
}
