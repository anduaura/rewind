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

//! `rewind push` — upload a `.rwd` snapshot to cloud object storage.
//!
//! Supported destinations:
//!   s3://bucket/path/to/snapshot.rwd   (AWS S3 — env: AWS_REGION, AWS credentials)
//!   gs://bucket/path/to/snapshot.rwd   (GCS    — env: GOOGLE_APPLICATION_CREDENTIALS)
//!   az://container/path/snapshot.rwd   (Azure  — env: AZURE_STORAGE_ACCOUNT + key/SAS)
//!
//! If the destination ends with `/`, the local filename is appended automatically.

use anyhow::{Context, Result};
use bytes::Bytes;
use object_store::{
    aws::AmazonS3Builder, azure::MicrosoftAzureBuilder, gcp::GoogleCloudStorageBuilder,
    path::Path as ObjPath, ObjectStore,
};
use std::path::Path;
use std::sync::Arc;

use crate::cli::PushArgs;

pub async fn run(args: PushArgs) -> Result<()> {
    let dest = resolve_destination(&args.destination, &args.snapshot);

    let data = tokio::fs::read(&args.snapshot)
        .await
        .with_context(|| format!("cannot read {}", args.snapshot.display()))?;

    let size_kb = data.len() / 1024;
    let bytes = Bytes::from(data);

    let (store, obj_path) = build_store(&dest)?;

    println!(
        "Uploading {} ({} KB) → {}",
        args.snapshot.display(),
        size_kb,
        dest
    );

    store
        .put(&obj_path, bytes.into())
        .await
        .with_context(|| format!("upload to {dest} failed"))?;

    println!("Done.");
    Ok(())
}

/// If the destination ends with `/`, append the snapshot's filename.
fn resolve_destination(dest: &str, snapshot: &Path) -> String {
    if dest.ends_with('/') {
        let fname = snapshot
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("snapshot.rwd");
        format!("{dest}{fname}")
    } else {
        dest.to_string()
    }
}

fn build_store(dest: &str) -> Result<(Arc<dyn ObjectStore>, ObjPath)> {
    if let Some(rest) = dest.strip_prefix("s3://") {
        let (bucket, key) = split_bucket_key(rest, "s3")?;
        let store = AmazonS3Builder::from_env()
            .with_bucket_name(bucket)
            .build()
            .context(
                "failed to build S3 client — set AWS_REGION and AWS credentials \
                 (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, or use an IAM role)",
            )?;
        Ok((Arc::new(store), ObjPath::from(key)))
    } else if let Some(rest) = dest.strip_prefix("gs://") {
        let (bucket, key) = split_bucket_key(rest, "gs")?;
        let store = GoogleCloudStorageBuilder::from_env()
            .with_bucket_name(bucket)
            .build()
            .context(
                "failed to build GCS client — set GOOGLE_APPLICATION_CREDENTIALS \
                 to a service-account JSON file path",
            )?;
        Ok((Arc::new(store), ObjPath::from(key)))
    } else if let Some(rest) = dest.strip_prefix("az://") {
        let (container, key) = split_bucket_key(rest, "az")?;
        let store = MicrosoftAzureBuilder::from_env()
            .with_container_name(container)
            .build()
            .context(
                "failed to build Azure Blob client — set AZURE_STORAGE_ACCOUNT \
                 and AZURE_STORAGE_ACCESS_KEY (or AZURE_STORAGE_SAS_KEY)",
            )?;
        Ok((Arc::new(store), ObjPath::from(key)))
    } else {
        anyhow::bail!(
            "unsupported destination scheme '{}': expected s3://, gs://, or az://",
            dest.split("://").next().unwrap_or(dest)
        )
    }
}

fn split_bucket_key<'a>(rest: &'a str, scheme: &str) -> Result<(&'a str, &'a str)> {
    let slash = rest.find('/').with_context(|| {
        format!("destination must be {scheme}://<bucket>/<key>, got {scheme}://{rest}")
    })?;
    let bucket = &rest[..slash];
    let key = &rest[slash + 1..];
    if key.is_empty() {
        anyhow::bail!("destination key is empty — did you mean to end with a filename?");
    }
    Ok((bucket, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_appends_filename_when_trailing_slash() {
        let p = Path::new("/tmp/incident-2026.rwd");
        assert_eq!(
            resolve_destination("s3://my-bucket/incidents/", p),
            "s3://my-bucket/incidents/incident-2026.rwd"
        );
    }

    #[test]
    fn resolve_leaves_full_path_unchanged() {
        let p = Path::new("/tmp/foo.rwd");
        assert_eq!(
            resolve_destination("s3://my-bucket/path/snap.rwd", p),
            "s3://my-bucket/path/snap.rwd"
        );
    }

    #[test]
    fn unknown_scheme_errors() {
        assert!(build_store("ftp://bucket/key.rwd").is_err());
    }

    #[test]
    fn missing_key_errors() {
        assert!(build_store("s3://bucket-only").is_err());
    }

    #[test]
    fn empty_key_errors() {
        assert!(build_store("s3://bucket/").is_err());
    }
}
