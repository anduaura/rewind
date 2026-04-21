// Copyright 2026 The rewind Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! OIDC / JWT Bearer-token validation for `rewind server`.
//!
//! When `--oidc-issuer` is supplied, the server fetches the provider's JWKS
//! and validates every incoming `Authorization: Bearer <token>` as an RS256 JWT.
//! The team name is extracted from a configurable claim (default: `team`), with
//! a fallback to the `sub` claim so any standard OIDC token works out of the box.
//!
//! Key rotation is handled automatically: JWKS keys are cached for 5 minutes
//! then re-fetched transparently on the next request.
//!
//! Compatible with Okta, Azure AD, Google Workspace, Auth0, Keycloak, and any
//! provider that implements RFC 8414 / OpenID Connect Discovery.

use anyhow::{Context, Result};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const JWKS_TTL: Duration = Duration::from_secs(300);

// ── Wire types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

/// Minimal JWK representation — we only need RSA public key fields.
#[derive(Deserialize, Clone)]
struct JwkKey {
    kty: String,
    #[serde(rename = "use")]
    key_use: Option<String>,
    #[allow(dead_code)]
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<JwkKey>,
}

/// JWT claims we care about.
#[derive(Deserialize)]
struct Claims {
    sub: String,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

// ── OidcValidator ─────────────────────────────────────────────────────────

pub struct OidcValidator {
    issuer: String,
    audience: String,
    team_claim: String,
    cache: RwLock<Option<(Vec<JwkKey>, Instant)>>,
}

impl OidcValidator {
    pub fn new(issuer: String, audience: String, team_claim: String) -> Self {
        Self {
            issuer,
            audience,
            team_claim,
            cache: RwLock::new(None),
        }
    }

    /// Validate a raw Bearer token string.
    /// Returns the resolved team name on success, `None` on any failure.
    pub async fn validate(&self, token: &str) -> Option<String> {
        let keys = self.fresh_keys().await?;

        for key in &keys {
            if let Some(team) = try_decode(token, key, &self.issuer, &self.audience, &self.team_claim) {
                return Some(team);
            }
        }
        None
    }

    async fn fresh_keys(&self) -> Option<Vec<JwkKey>> {
        // Fast path: cache is still warm.
        {
            let g = self.cache.read().await;
            if let Some((keys, fetched_at)) = g.as_ref() {
                if fetched_at.elapsed() < JWKS_TTL {
                    return Some(keys.clone());
                }
            }
        }

        // Slow path: refresh.
        match fetch_jwks(&self.issuer).await {
            Ok(keys) => {
                let mut g = self.cache.write().await;
                *g = Some((keys.clone(), Instant::now()));
                Some(keys)
            }
            Err(e) => {
                tracing::warn!("JWKS refresh failed: {e}");
                // Return stale keys rather than blocking all auth on a transient error.
                let g = self.cache.read().await;
                g.as_ref().map(|(k, _)| k.clone())
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn try_decode(
    token: &str,
    key: &JwkKey,
    issuer: &str,
    audience: &str,
    team_claim: &str,
) -> Option<String> {
    if key.kty != "RSA" {
        return None;
    }
    // Skip keys not intended for signatures (e.g. "enc" keys in mixed sets).
    if let Some(u) = &key.key_use {
        if u != "sig" {
            return None;
        }
    }

    let n = key.n.as_deref()?;
    let e = key.e.as_deref()?;
    let decoding_key = DecodingKey::from_rsa_components(n, e).ok()?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[issuer]);

    let data = decode::<Claims>(token, &decoding_key, &validation).ok()?;

    let team = data
        .claims
        .extra
        .get(team_claim)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or(data.claims.sub);

    Some(team)
}

async fn fetch_jwks(issuer: &str) -> Result<Vec<JwkKey>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );

    let discovery: OidcDiscovery = client
        .get(&discovery_url)
        .send()
        .await
        .context("fetching OIDC discovery document")?
        .error_for_status()
        .context("OIDC discovery endpoint error")?
        .json()
        .await
        .context("parsing OIDC discovery document")?;

    let jwks: JwkSet = client
        .get(&discovery.jwks_uri)
        .send()
        .await
        .context("fetching JWKS")?
        .error_for_status()
        .context("JWKS endpoint error")?
        .json()
        .await
        .context("parsing JWKS")?;

    Ok(jwks.keys)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_decode_skips_non_rsa_keys() {
        let key = JwkKey {
            kty: "EC".to_string(),
            key_use: Some("sig".to_string()),
            kid: None,
            n: None,
            e: None,
        };
        assert!(try_decode("tok", &key, "iss", "aud", "team").is_none());
    }

    #[test]
    fn try_decode_skips_enc_keys() {
        let key = JwkKey {
            kty: "RSA".to_string(),
            key_use: Some("enc".to_string()),
            kid: None,
            n: Some("n".to_string()),
            e: Some("e".to_string()),
        };
        // enc keys should be skipped even with RSA kty
        assert!(try_decode("tok", &key, "iss", "aud", "team").is_none());
    }

    #[test]
    fn try_decode_missing_n_returns_none() {
        let key = JwkKey {
            kty: "RSA".to_string(),
            key_use: Some("sig".to_string()),
            kid: None,
            n: None,
            e: Some("AQAB".to_string()),
        };
        assert!(try_decode("tok", &key, "iss", "aud", "team").is_none());
    }

    #[test]
    fn oidc_validator_new() {
        let v = OidcValidator::new(
            "https://accounts.google.com".to_string(),
            "my-app".to_string(),
            "team".to_string(),
        );
        assert_eq!(v.issuer, "https://accounts.google.com");
        assert_eq!(v.audience, "my-app");
        assert_eq!(v.team_claim, "team");
    }
}
