//! [`S3Store`] — a [`concord_core::store::Store`] backed by an S3-compatible
//! HTTP gateway (CloudVerve in production, MinIO / real-AWS for testing).
//!
//! Key layout (documented per the brief):
//! - chunks    → `chunks/<first-4-hex>/<full-64-hex>`
//! - manifests → `manifests/<name>/<version>.toml`
//!
//! The first-4-hex shard prefix on chunk keys keeps any single S3 prefix
//! from accumulating hundreds of thousands of objects, which most S3
//! backends paginate / range-partition by prefix.

use std::collections::BTreeMap;

use async_trait::async_trait;
use bytes::Bytes;
use concord_core::chunker::ChunkHash;
use concord_core::store::{Store, StoreError};
use reqwest::{Client, StatusCode};
use thiserror::Error;
use url::Url;

use crate::sigv4::{self, Credentials, SignableRequest, EMPTY_PAYLOAD_SHA256};

/// Configuration for an [`S3Store`].
#[derive(Clone, Debug)]
pub struct S3Config {
    /// Endpoint root, e.g. `https://s3.example.org`.
    pub endpoint: String,
    /// Bucket name, e.g. `concord`.
    pub bucket: String,
    /// AWS region string. CloudVerve accepts any non-empty string; default
    /// `us-east-1` is a safe fallback for MinIO-class backends.
    pub region: String,
    /// SigV4 credentials (access key + secret).
    pub credentials: Credentials,
}

/// Errors from S3Store construction or HTTP exchange. Per-call HTTP errors
/// get mapped into `StoreError::Backend` so callers can stay on the
/// `Store`-trait surface.
#[derive(Debug, Error)]
pub enum S3Error {
    #[error("bad endpoint url: {0}")]
    BadEndpoint(String),
    #[error("reqwest build: {0}")]
    Reqwest(#[from] reqwest::Error),
}

/// S3-backed Concord [`Store`].
#[derive(Debug)]
pub struct S3Store {
    cfg: S3Config,
    http: Client,
    endpoint_host: String,
    /// `https://host` portion of the endpoint, no path, no trailing slash.
    endpoint_origin: String,
}

impl S3Store {
    /// Build a new store. Validates the endpoint URL once at construction
    /// time so per-request error paths can assume a parseable URL.
    pub fn new(cfg: S3Config) -> Result<Self, S3Error> {
        let url = Url::parse(&cfg.endpoint).map_err(|e| S3Error::BadEndpoint(e.to_string()))?;
        let host = url
            .host_str()
            .ok_or_else(|| S3Error::BadEndpoint("endpoint has no host".into()))?
            .to_string();
        let endpoint_host = match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host,
        };
        let scheme = url.scheme();
        let endpoint_origin = format!("{scheme}://{endpoint_host}");
        let http = Client::builder().build()?;
        Ok(Self {
            cfg,
            http,
            endpoint_host,
            endpoint_origin,
        })
    }

    /// Storage key for a chunk.
    pub fn chunk_key(&self, hash: &ChunkHash) -> String {
        let hex = hex::encode(hash.as_bytes());
        // First-4-hex prefix shard; the full hex is the leaf name.
        format!("chunks/{}/{}", &hex[..4], hex)
    }

    /// Storage key for a manifest.
    pub fn manifest_key(&self, name: &str, version: &str) -> String {
        format!("manifests/{name}/{version}.toml")
    }

    /// Build the absolute URL for a given object key.
    fn url_for(&self, key: &str) -> (String, String) {
        // Path-style: `/<bucket>/<key>`. The key is percent-encoded
        // component-by-component so `/` characters in the key stay as
        // path separators (S3 treats `/` as a virtual delimiter).
        let encoded_key = encode_key(key);
        let path = format!("/{}/{}", self.cfg.bucket, encoded_key);
        let url = format!("{}{}", self.endpoint_origin, path);
        (url, path)
    }

    fn now() -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }

    /// Sign + send a request. Body is consumed for the payload digest so
    /// the signed request matches what we actually transmit.
    async fn signed_request(
        &self,
        method: &str,
        key: &str,
        body: Option<Bytes>,
        extra_headers: BTreeMap<String, String>,
    ) -> Result<reqwest::Response, StoreError> {
        let (url, path) = self.url_for(key);

        let payload_sha = match &body {
            Some(b) => sigv4::sha256_hex(b),
            None => EMPTY_PAYLOAD_SHA256.to_string(),
        };

        let mut headers: BTreeMap<String, String> = BTreeMap::new();
        headers.insert("host".into(), self.endpoint_host.clone());
        for (k, v) in &extra_headers {
            headers.insert(k.to_ascii_lowercase(), v.clone());
        }

        let signed = sigv4::sign(
            &SignableRequest {
                method,
                path: &path,
                query: "",
                headers: headers.clone(),
                payload_sha256: payload_sha.clone(),
            },
            &self.cfg.credentials,
            &self.cfg.region,
            "s3",
            Self::now(),
        );

        let mut builder = self.http.request(
            reqwest::Method::from_bytes(method.as_bytes())
                .map_err(|e| StoreError::Backend(format!("bad method {method}: {e}")))?,
            &url,
        );

        // Attach signing-related headers + everything the caller passed.
        builder = builder
            .header("authorization", &signed.authorization)
            .header("x-amz-date", &signed.x_amz_date)
            .header("x-amz-content-sha256", &signed.x_amz_content_sha256);
        for (k, v) in &extra_headers {
            builder = builder.header(k, v);
        }
        if let Some(b) = body {
            builder = builder.body(b);
        }

        builder
            .send()
            .await
            .map_err(|e| StoreError::Backend(format!("http: {e}")))
    }
}

#[async_trait]
impl Store for S3Store {
    async fn has_chunk(&self, hash: &ChunkHash) -> Result<bool, StoreError> {
        let key = self.chunk_key(hash);
        let resp = self
            .signed_request("HEAD", &key, None, BTreeMap::new())
            .await?;
        match resp.status() {
            s if s.is_success() => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            other => Err(StoreError::Backend(format!("HEAD chunk: HTTP {other}"))),
        }
    }

    async fn put_chunk(&self, hash: &ChunkHash, body: Bytes) -> Result<(), StoreError> {
        let key = self.chunk_key(hash);
        let resp = self
            .signed_request("PUT", &key, Some(body), BTreeMap::new())
            .await?;
        match resp.status() {
            s if s.is_success() => Ok(()),
            StatusCode::PRECONDITION_FAILED => Ok(()),
            other => {
                let body = resp.text().await.unwrap_or_default();
                Err(StoreError::Backend(format!(
                    "PUT chunk: HTTP {other}: {body}"
                )))
            }
        }
    }

    async fn get_chunk(&self, hash: &ChunkHash) -> Result<Bytes, StoreError> {
        let key = self.chunk_key(hash);
        let resp = self
            .signed_request("GET", &key, None, BTreeMap::new())
            .await?;
        match resp.status() {
            StatusCode::NOT_FOUND => Err(StoreError::NotFound),
            s if s.is_success() => resp
                .bytes()
                .await
                .map_err(|e| StoreError::Backend(format!("read chunk body: {e}"))),
            other => Err(StoreError::Backend(format!("GET chunk: HTTP {other}"))),
        }
    }

    async fn put_manifest(&self, name: &str, version: &str, body: Bytes) -> Result<(), StoreError> {
        let key = self.manifest_key(name, version);
        // Intentionally NOT signing a content-type header. CloudVerve's
        // SigV4 verifier reconstructs canonical headers from a fixed set
        // (host + x-amz-*) and ignores client-provided content-type; if
        // we include it in our SignedHeaders list the verifier computes a
        // different canonical request → 403. Sending the body untyped
        // (or with reqwest's default) is fine — the manifest TOML is
        // identified by the .toml suffix in the key, not the header.
        let resp = self
            .signed_request("PUT", &key, Some(body), BTreeMap::new())
            .await?;
        match resp.status() {
            s if s.is_success() => Ok(()),
            other => {
                let body = resp.text().await.unwrap_or_default();
                Err(StoreError::Backend(format!(
                    "PUT manifest: HTTP {other}: {body}"
                )))
            }
        }
    }

    async fn get_manifest(&self, name: &str, version: &str) -> Result<Bytes, StoreError> {
        let key = self.manifest_key(name, version);
        let resp = self
            .signed_request("GET", &key, None, BTreeMap::new())
            .await?;
        match resp.status() {
            StatusCode::NOT_FOUND => Err(StoreError::NotFound),
            s if s.is_success() => resp
                .bytes()
                .await
                .map_err(|e| StoreError::Backend(format!("read manifest body: {e}"))),
            other => Err(StoreError::Backend(format!("GET manifest: HTTP {other}"))),
        }
    }
}

/// Percent-encode an object key for use in the S3 URL path. RFC 3986
/// unreserved + `/` (S3 treats `/` as a delimiter so we keep it
/// unencoded).
fn encode_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for b in key.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(b as char);
            }
            other => {
                out.push_str(&format!("%{:02X}", other));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test fixture uses placeholder endpoint + bucket names. The real
    // operator's endpoint/bucket are operator-internal and never appear
    // in this public repo (see security: client must not know bucket).
    fn cfg() -> S3Config {
        S3Config {
            endpoint: "https://s3.example.org".into(),
            bucket: "test-bucket".into(),
            region: "us-east-1".into(),
            credentials: Credentials {
                access_key_id: "AKID".into(),
                secret_access_key: "SECRET".into(),
            },
        }
    }

    #[test]
    fn new_parses_endpoint() {
        let s = S3Store::new(cfg()).unwrap();
        assert_eq!(s.endpoint_host, "s3.example.org");
        assert_eq!(s.endpoint_origin, "https://s3.example.org");
    }

    #[test]
    fn new_handles_endpoint_with_port() {
        let mut c = cfg();
        c.endpoint = "http://127.0.0.1:9000".into();
        let s = S3Store::new(c).unwrap();
        assert_eq!(s.endpoint_host, "127.0.0.1:9000");
        assert_eq!(s.endpoint_origin, "http://127.0.0.1:9000");
    }

    #[test]
    fn new_rejects_garbage_endpoint() {
        let mut c = cfg();
        c.endpoint = "not a url".into();
        assert!(matches!(S3Store::new(c), Err(S3Error::BadEndpoint(_))));
    }

    #[test]
    fn chunk_key_layout() {
        let s = S3Store::new(cfg()).unwrap();
        let h = ChunkHash::of(b"some bytes");
        let key = s.chunk_key(&h);
        let hex = hex::encode(h.as_bytes());
        assert_eq!(key, format!("chunks/{}/{}", &hex[..4], hex));
    }

    #[test]
    fn manifest_key_layout() {
        let s = S3Store::new(cfg()).unwrap();
        let k = s.manifest_key("org/name", "v0.3.1");
        assert_eq!(k, "manifests/org/name/v0.3.1.toml");
    }

    #[test]
    fn url_for_uses_path_style() {
        let s = S3Store::new(cfg()).unwrap();
        let (url, path) = s.url_for("manifests/org/name/v0.3.1.toml");
        assert_eq!(
            url,
            "https://s3.example.org/test-bucket/manifests/org/name/v0.3.1.toml"
        );
        assert_eq!(path, "/test-bucket/manifests/org/name/v0.3.1.toml");
    }

    #[test]
    fn encode_key_preserves_path_separators() {
        assert_eq!(
            encode_key("manifests/org/name/v1.toml"),
            "manifests/org/name/v1.toml"
        );
    }

    #[test]
    fn encode_key_percent_encodes_spaces() {
        assert_eq!(
            encode_key("manifests/has space/x"),
            "manifests/has%20space/x"
        );
    }
}
