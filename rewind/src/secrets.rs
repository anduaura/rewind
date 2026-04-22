//! Secret management — resolve `--key` values from external secret stores.
//!
//! Supported URI schemes:
//!   `vault://path/to/secret`        — HashiCorp Vault KV (v1 or v2)
//!   `aws://region/secret-name`      — AWS Secrets Manager (SigV4 auth)
//!   `azure://vault-name/secret-name`— Azure Key Vault (client-credentials OAuth2)
//!
//! A plain string (no URI scheme) is returned unchanged, so existing callers
//! that pass raw passphrases continue to work without modification.
//!
//! Required environment variables per backend:
//!   Vault:  VAULT_ADDR, VAULT_TOKEN
//!   AWS:    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY [, AWS_REGION]
//!   Azure:  AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET

use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

// ── Public API ────────────────────────────────────────────────────────────────

/// Resolve an optional key value.  URI schemes are fetched from the secret
/// store; plain strings and `None` are returned unchanged.
pub async fn resolve_key_opt(key: Option<String>) -> Result<Option<String>> {
    match key {
        None => Ok(None),
        Some(v) => Ok(Some(resolve(&v).await?)),
    }
}

/// Resolve a single key string.  Returns the secret value on success.
pub async fn resolve(uri: &str) -> Result<String> {
    if let Some(path) = uri.strip_prefix("vault://") {
        resolve_vault(path).await
    } else if let Some(rest) = uri.strip_prefix("aws://") {
        resolve_aws(rest).await
    } else if let Some(rest) = uri.strip_prefix("azure://") {
        resolve_azure(rest).await
    } else {
        Ok(uri.to_string())
    }
}

// ── Vault ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct VaultResponse {
    data: serde_json::Value,
}

async fn resolve_vault(path: &str) -> Result<String> {
    let addr = std::env::var("VAULT_ADDR")
        .context("VAULT_ADDR is required for vault:// secrets")?;
    let token = std::env::var("VAULT_TOKEN")
        .context("VAULT_TOKEN is required for vault:// secrets")?;

    let url = format!("{}/v1/{}", addr.trim_end_matches('/'), path);
    let resp: VaultResponse = http_client()?
        .get(&url)
        .header("X-Vault-Token", token)
        .send()
        .await
        .context("Vault request failed")?
        .error_for_status()
        .context("Vault returned error status")?
        .json()
        .await
        .context("parsing Vault response")?;

    // KV v2: {"data": {"data": {"value": "..."}}}
    if let Some(v) = resp.data.get("data").and_then(|d| d.get("value")).and_then(|v| v.as_str()) {
        return Ok(v.to_string());
    }
    // KV v1: {"data": {"value": "..."}}
    if let Some(v) = resp.data.get("value").and_then(|v| v.as_str()) {
        return Ok(v.to_string());
    }
    bail!("Vault secret at {path} has no 'value' field (tried KV v1 and v2)")
}

// ── AWS Secrets Manager ───────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsSecretResponse {
    secret_string: Option<String>,
}

async fn resolve_aws(rest: &str) -> Result<String> {
    // URI: aws://region/secret-name  OR  aws://secret-name (uses AWS_REGION)
    let (region, secret_id) = if let Some((r, s)) = rest.split_once('/') {
        (r.to_string(), s.to_string())
    } else {
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .context("AWS_REGION is required when region is not in aws:// URI")?;
        (region, rest.to_string())
    };

    let access_key = std::env::var("AWS_ACCESS_KEY_ID")
        .context("AWS_ACCESS_KEY_ID is required for aws:// secrets")?;
    let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
        .context("AWS_SECRET_ACCESS_KEY is required for aws:// secrets")?;

    let host = format!("secretsmanager.{region}.amazonaws.com");
    let url = format!("https://{host}/");
    let body = serde_json::json!({"SecretId": secret_id}).to_string();

    let now = chrono::Utc::now();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();

    let auth = sigv4_authorization(&SigV4Params {
        access_key: &access_key,
        secret_key: &secret_key,
        region: &region,
        service: "secretsmanager",
        host: &host,
        datetime: &datetime,
        date: &date,
        body: &body,
    })?;

    let resp: AwsSecretResponse = http_client()?
        .post(&url)
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Date", &datetime)
        .header("X-Amz-Target", "secretsmanager.GetSecretValue")
        .header("Authorization", auth)
        .body(body)
        .send()
        .await
        .context("AWS Secrets Manager request failed")?
        .error_for_status()
        .context("AWS Secrets Manager returned error status")?
        .json()
        .await
        .context("parsing AWS Secrets Manager response")?;

    resp.secret_string
        .context("AWS secret has no SecretString (binary secrets are not supported)")
}

struct SigV4Params<'a> {
    access_key: &'a str,
    secret_key: &'a str,
    region: &'a str,
    service: &'a str,
    host: &'a str,
    datetime: &'a str,
    date: &'a str,
    body: &'a str,
}

/// Build an AWS SigV4 Authorization header value.
fn sigv4_authorization(p: &SigV4Params<'_>) -> Result<String> {
    let payload_hash = hex_sha256(p.body.as_bytes());
    let canonical_headers = format!(
        "content-type:application/x-amz-json-1.1\nhost:{}\nx-amz-date:{}\nx-amz-target:secretsmanager.GetSecretValue\n",
        p.host, p.datetime
    );
    let signed_headers = "content-type;host;x-amz-date;x-amz-target";
    let canonical_request = format!(
        "POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let scope = format!("{}/{}/{}/aws4_request", p.date, p.region, p.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        p.datetime,
        hex_sha256(canonical_request.as_bytes())
    );

    let signing_key = {
        let k = hmac_sha256(format!("AWS4{}", p.secret_key).as_bytes(), p.date.as_bytes())?;
        let k = hmac_sha256(&k, p.region.as_bytes())?;
        let k = hmac_sha256(&k, p.service.as_bytes())?;
        hmac_sha256(&k, b"aws4_request")?
    };
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

    Ok(format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        p.access_key
    ))
}

fn hex_sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

// ── Azure Key Vault ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AzureTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct AzureSecretResponse {
    value: String,
}

async fn resolve_azure(rest: &str) -> Result<String> {
    // URI: azure://vault-name/secret-name
    let (vault_name, secret_name) = rest
        .split_once('/')
        .context("azure:// URI must be azure://vault-name/secret-name")?;

    let tenant_id = std::env::var("AZURE_TENANT_ID")
        .context("AZURE_TENANT_ID is required for azure:// secrets")?;
    let client_id = std::env::var("AZURE_CLIENT_ID")
        .context("AZURE_CLIENT_ID is required for azure:// secrets")?;
    let client_secret = std::env::var("AZURE_CLIENT_SECRET")
        .context("AZURE_CLIENT_SECRET is required for azure:// secrets")?;

    let client = http_client()?;

    let token_url = format!(
        "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    );
    let token_resp: AzureTokenResponse = client
        .post(&token_url)
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("scope", "https://vault.azure.net/.default"),
            ("grant_type", "client_credentials"),
        ])
        .send()
        .await
        .context("Azure OAuth2 token request failed")?
        .error_for_status()
        .context("Azure OAuth2 returned error status")?
        .json()
        .await
        .context("parsing Azure token response")?;

    let secret_url = format!(
        "https://{vault_name}.vault.azure.net/secrets/{secret_name}?api-version=7.4"
    );
    let secret_resp: AzureSecretResponse = client
        .get(&secret_url)
        .bearer_auth(&token_resp.access_token)
        .send()
        .await
        .context("Azure Key Vault secret request failed")?
        .error_for_status()
        .context("Azure Key Vault returned error status")?
        .json()
        .await
        .context("parsing Azure Key Vault response")?;

    Ok(secret_resp.value)
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("building HTTP client")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plain_passphrase_returned_unchanged() {
        let result = resolve("mysecretpassphrase").await.unwrap();
        assert_eq!(result, "mysecretpassphrase");
    }

    #[tokio::test]
    async fn vault_uri_without_addr_errors() {
        std::env::remove_var("VAULT_ADDR");
        let err = resolve("vault://secret/data/mykey").await.unwrap_err();
        assert!(err.to_string().contains("VAULT_ADDR"));
    }

    #[tokio::test]
    async fn aws_uri_without_credentials_errors() {
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        // Region embedded in URI, credentials missing
        let err = resolve("aws://us-east-1/my-secret").await.unwrap_err();
        assert!(err.to_string().contains("AWS_ACCESS_KEY_ID"));
    }

    #[tokio::test]
    async fn azure_uri_without_tenant_errors() {
        std::env::remove_var("AZURE_TENANT_ID");
        let err = resolve("azure://myvault/mysecret").await.unwrap_err();
        assert!(err.to_string().contains("AZURE_TENANT_ID"));
    }

    #[tokio::test]
    async fn resolve_key_opt_none_passthrough() {
        let result = resolve_key_opt(None).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn resolve_key_opt_plain_string() {
        let result = resolve_key_opt(Some("passphrase".to_string())).await.unwrap();
        assert_eq!(result.as_deref(), Some("passphrase"));
    }

    #[test]
    fn sigv4_produces_deterministic_output() {
        let auth = sigv4_authorization(&SigV4Params {
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "secretsmanager",
            host: "secretsmanager.us-east-1.amazonaws.com",
            datetime: "20260422T120000Z",
            date: "20260422",
            body: r#"{"SecretId":"test-secret"}"#,
        })
        .unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260422/"));
    }

    #[test]
    fn azure_uri_missing_slash_errors() {
        // azure://vault-only — no secret name
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(resolve("azure://vaultonly"))
            .unwrap_err();
        assert!(err.to_string().contains("azure://vault-name/secret-name"));
    }
}
