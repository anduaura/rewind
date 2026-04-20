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

//! Snapshot encryption at rest using the age format (passphrase-based AES-256-GCM).
//!
//! Key resolution order:
//!   1. Explicit `--key` / `--encrypt-key` CLI flag
//!   2. `REWIND_SNAPSHOT_KEY` environment variable
//!   3. No encryption (plaintext)

use age::secrecy::Secret;
use anyhow::{bail, Context, Result};
use std::io::{Read, Write};

const AGE_MAGIC: &[u8] = b"age-encryption.org";

/// Encrypt `data` with the given passphrase using age (AES-256-GCM stream).
pub fn encrypt(data: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase.to_owned()));
    let mut output = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut output)
        .context("failed to initialise age encryptor")?;
    writer.write_all(data).context("encrypt write")?;
    writer.finish().context("encrypt finish")?;
    Ok(output)
}

/// Decrypt age-encrypted `data` with the given passphrase.
pub fn decrypt(data: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let cursor = std::io::BufReader::new(std::io::Cursor::new(data));
    let decryptor = age::Decryptor::new(cursor).context("invalid age ciphertext")?;
    match decryptor {
        age::Decryptor::Passphrase(d) => {
            let mut reader = d
                .decrypt(&Secret::new(passphrase.to_owned()), None)
                .context("decryption failed — wrong passphrase?")?;
            let mut out = Vec::new();
            reader.read_to_end(&mut out).context("decrypt read")?;
            Ok(out)
        }
        _ => bail!("snapshot is not passphrase-encrypted"),
    }
}

/// Returns true if the byte slice starts with the age binary format magic.
pub fn is_encrypted(data: &[u8]) -> bool {
    data.starts_with(AGE_MAGIC)
}

/// Resolve the encryption key: explicit flag wins, then REWIND_SNAPSHOT_KEY env var.
pub fn resolve_key(explicit: Option<String>) -> Option<String> {
    explicit.or_else(|| std::env::var("REWIND_SNAPSHOT_KEY").ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plain = b"hello rewind snapshot";
        let ct = encrypt(plain, "s3cr3t").unwrap();
        assert!(is_encrypted(&ct));
        let recovered = decrypt(&ct, "s3cr3t").unwrap();
        assert_eq!(recovered, plain);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let ct = encrypt(b"data", "correct").unwrap();
        assert!(decrypt(&ct, "wrong").is_err());
    }

    #[test]
    fn is_encrypted_detects_plaintext() {
        assert!(!is_encrypted(b"{\"version\":1}"));
    }

    #[test]
    fn resolve_key_prefers_explicit() {
        std::env::set_var("REWIND_SNAPSHOT_KEY", "from_env");
        let key = resolve_key(Some("explicit".to_string()));
        std::env::remove_var("REWIND_SNAPSHOT_KEY");
        assert_eq!(key.as_deref(), Some("explicit"));
    }

    #[test]
    fn resolve_key_falls_back_to_env() {
        std::env::set_var("REWIND_SNAPSHOT_KEY", "env_key");
        let key = resolve_key(None);
        std::env::remove_var("REWIND_SNAPSHOT_KEY");
        assert_eq!(key.as_deref(), Some("env_key"));
    }

    #[test]
    fn resolve_key_none_when_nothing_set() {
        std::env::remove_var("REWIND_SNAPSHOT_KEY");
        assert!(resolve_key(None).is_none());
    }
}
