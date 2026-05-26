//! Minimal AWS SigV4 request signer for S3.
//!
//! Hand-rolled to avoid pulling the full `aws-sigv4` + `aws-smithy-*` tree
//! into the workspace. Only what S3 needs: header-based signing with the
//! `x-amz-content-sha256` payload digest, UNSIGNED-PAYLOAD supported for
//! streaming PUTs, single-region single-service scope (`s3` + caller's
//! region). Path-style URLs (CloudVerve nodes are addressed by host, the
//! bucket sits in the URL path) — virtual-hosted-style is intentionally
//! out of scope here.
//!
//! Reference: AWS docs "Signing AWS API requests with Signature Version 4".

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Sentinel hash for unsigned payloads. S3 accepts this when the caller
/// would rather not buffer + hash the body (large streaming PUTs).
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Hash of an empty body — pre-computed to avoid hashing nothing.
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// SigV4 credentials. The `secret` is consumed only to derive the signing
/// key per request — never logged, never returned.
#[derive(Clone, Debug)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
}

/// A request, decomposed to the bits SigV4 needs to canonicalise + sign.
/// `headers` MUST include `host`. The signer adds `x-amz-date` and
/// `x-amz-content-sha256` itself.
#[derive(Debug)]
pub struct SignableRequest<'a> {
    pub method: &'a str,
    /// URI path **already percent-encoded**, starting with `/`. Caller is
    /// responsible for encoding object keys correctly.
    pub path: &'a str,
    /// Raw query string (without leading `?`), already percent-encoded.
    /// Pass `""` if there's no query.
    pub query: &'a str,
    /// Headers to include in the canonical request. Header names are
    /// matched case-insensitively per SigV4 rules.
    pub headers: BTreeMap<String, String>,
    /// `sha256(body)` as lowercase hex, or [`UNSIGNED_PAYLOAD`].
    pub payload_sha256: String,
}

/// Outcome of signing: the `Authorization` header value plus the
/// `x-amz-date` and `x-amz-content-sha256` headers the caller must attach
/// (in addition to whatever was in `SignableRequest::headers`).
#[derive(Debug)]
pub struct SignedHeaders {
    pub authorization: String,
    pub x_amz_date: String,
    pub x_amz_content_sha256: String,
}

/// Sign `req` for the given credentials, region, service (`s3`) and
/// timestamp. `now` is taken as a parameter so tests can pin it; in
/// production code, pass `time::OffsetDateTime::now_utc()`.
pub fn sign(
    req: &SignableRequest<'_>,
    creds: &Credentials,
    region: &str,
    service: &str,
    now: time::OffsetDateTime,
) -> SignedHeaders {
    let amz_date = format_amz_date(now);
    let date_only = &amz_date[..8];
    let scope = format!("{date_only}/{region}/{service}/aws4_request");

    // ---- canonical request ----
    let mut headers = req.headers.clone();
    headers.insert("x-amz-date".into(), amz_date.clone());
    headers.insert("x-amz-content-sha256".into(), req.payload_sha256.clone());

    // Header names must be lowercase, values trimmed of surrounding ws.
    let canon_headers: BTreeMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();

    let signed_headers_list: Vec<&str> = canon_headers.keys().map(String::as_str).collect();
    let signed_headers = signed_headers_list.join(";");

    let mut canonical = String::new();
    canonical.push_str(req.method);
    canonical.push('\n');
    canonical.push_str(req.path);
    canonical.push('\n');
    canonical.push_str(req.query);
    canonical.push('\n');
    for (k, v) in &canon_headers {
        canonical.push_str(k);
        canonical.push(':');
        canonical.push_str(v);
        canonical.push('\n');
    }
    canonical.push('\n');
    canonical.push_str(&signed_headers);
    canonical.push('\n');
    canonical.push_str(&req.payload_sha256);

    let canonical_hash = sha256_hex(canonical.as_bytes());

    // ---- string to sign ----
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}");

    // ---- signing key ----
    let k_date = hmac(
        format!("AWS4{}", creds.secret_access_key).as_bytes(),
        date_only.as_bytes(),
    );
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");

    let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        creds.access_key_id, scope, signed_headers, signature
    );

    SignedHeaders {
        authorization,
        x_amz_date: amz_date,
        x_amz_content_sha256: req.payload_sha256.clone(),
    }
}

/// `sha256(data)` as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn format_amz_date(t: time::OffsetDateTime) -> String {
    // AWS basic ISO-8601 form: `YYYYMMDDTHHMMSSZ`. We render manually to
    // avoid pulling in `time`'s formatting feature flags beyond what the
    // workspace already exposes.
    use time::macros::format_description;
    let fmt = format_description!("[year][month][day]T[hour][minute][second]Z");
    t.format(fmt).expect("amz date format")
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn creds() -> Credentials {
        // From the AWS SigV4 test suite — `AKIDEXAMPLE` is the canonical
        // example access key, paired with the example secret.
        Credentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        }
    }

    #[test]
    fn empty_payload_constant_is_correct() {
        assert_eq!(EMPTY_PAYLOAD_SHA256, sha256_hex(b""));
    }

    #[test]
    fn sha256_hex_matches_known_value() {
        // sha256("hello") — known value, sanity check on the digest.
        assert_eq!(
            sha256_hex(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn signed_headers_include_required_fields() {
        // Just exercise the signing path end-to-end and assert the shape
        // of the output; we don't pin against AWS's vector because the
        // AWS vectors are for `service.amazonaws.com` general signing and
        // we'd have to encode an entire canonical request to compare.
        let mut hdrs = BTreeMap::new();
        hdrs.insert("host".into(), "s3.example.com".into());

        let req = SignableRequest {
            method: "GET",
            path: "/bucket/key",
            query: "",
            headers: hdrs,
            payload_sha256: EMPTY_PAYLOAD_SHA256.to_string(),
        };

        let signed = sign(
            &req,
            &creds(),
            "us-east-1",
            "s3",
            datetime!(2025-01-15 12:34:56 UTC),
        );

        assert!(signed.authorization.starts_with("AWS4-HMAC-SHA256 "));
        assert!(signed
            .authorization
            .contains("Credential=AKIDEXAMPLE/20250115/us-east-1/s3/aws4_request"));
        assert!(signed
            .authorization
            .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        assert!(signed.authorization.contains("Signature="));
        assert_eq!(signed.x_amz_date, "20250115T123456Z");
        assert_eq!(signed.x_amz_content_sha256, EMPTY_PAYLOAD_SHA256);
    }

    #[test]
    fn signature_changes_with_method() {
        let mut hdrs = BTreeMap::new();
        hdrs.insert("host".into(), "s3.example.com".into());
        let now = datetime!(2025-01-15 12:34:56 UTC);

        let get = sign(
            &SignableRequest {
                method: "GET",
                path: "/bucket/key",
                query: "",
                headers: hdrs.clone(),
                payload_sha256: EMPTY_PAYLOAD_SHA256.into(),
            },
            &creds(),
            "us-east-1",
            "s3",
            now,
        );
        let put = sign(
            &SignableRequest {
                method: "PUT",
                path: "/bucket/key",
                query: "",
                headers: hdrs,
                payload_sha256: EMPTY_PAYLOAD_SHA256.into(),
            },
            &creds(),
            "us-east-1",
            "s3",
            now,
        );
        assert_ne!(get.authorization, put.authorization);
    }

    #[test]
    fn signature_is_deterministic_for_same_input() {
        let mut hdrs = BTreeMap::new();
        hdrs.insert("host".into(), "s3.example.com".into());
        let req = SignableRequest {
            method: "GET",
            path: "/bucket/key",
            query: "",
            headers: hdrs,
            payload_sha256: EMPTY_PAYLOAD_SHA256.into(),
        };
        let a = sign(
            &req,
            &creds(),
            "us-east-1",
            "s3",
            datetime!(2025-01-15 12:34:56 UTC),
        );
        let b = sign(
            &req,
            &creds(),
            "us-east-1",
            "s3",
            datetime!(2025-01-15 12:34:56 UTC),
        );
        assert_eq!(a.authorization, b.authorization);
    }

    #[test]
    fn signature_changes_with_region() {
        let mut hdrs = BTreeMap::new();
        hdrs.insert("host".into(), "s3.example.com".into());
        let req = SignableRequest {
            method: "GET",
            path: "/bucket/key",
            query: "",
            headers: hdrs,
            payload_sha256: EMPTY_PAYLOAD_SHA256.into(),
        };
        let now = datetime!(2025-01-15 12:34:56 UTC);
        let us = sign(&req, &creds(), "us-east-1", "s3", now);
        let eu = sign(&req, &creds(), "eu-west-1", "s3", now);
        assert_ne!(us.authorization, eu.authorization);
    }

    #[test]
    fn amz_date_is_basic_iso8601() {
        let s = format_amz_date(datetime!(2026-05-13 09:14:22 UTC));
        assert_eq!(s, "20260513T091422Z");
    }
}
