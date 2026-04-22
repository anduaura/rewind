//! Compliance evidence export — `rewind compliance`.
//!
//! Produces a machine-readable JSON or Markdown report covering:
//!   - Encryption at rest (is a key configured? detected in snapshots?)
//!   - Access control (RBAC registry, OIDC issuer, single-token mode)
//!   - Transport security (TLS certificate present)
//!   - Audit log (event count, time range, action breakdown)
//!   - Retention policy (max-age, max-size limits configured)
//!   - Data isolation (per-team subdirectory structure)
//!   - Snapshot inventory (total count, size, teams, encrypted %)
//!
//! The report is suitable for attaching to SOC 2 / ISO 27001 / PCI-DSS audits.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;

use crate::cli::ComplianceArgs;
use crate::crypto;

// ── Output types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ComplianceReport {
    pub generated_at: String,
    pub rewind_version: &'static str,
    pub controls: Controls,
    pub snapshots: SnapshotInventory,
    pub audit: AuditSummary,
    pub summary: Summary,
}

#[derive(Debug, Serialize)]
pub struct Controls {
    pub encryption_at_rest: Control,
    pub access_control: AccessControlDetail,
    pub transport_security: Control,
    pub audit_log: Control,
    pub retention_policy: Control,
    pub data_isolation: Control,
}

#[derive(Debug, Serialize, Clone)]
pub struct Control {
    pub status: ControlStatus,
    pub detail: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    Enabled,
    Disabled,
    Unconfigured,
}

impl ControlStatus {
    fn is_passing(&self) -> bool {
        *self == ControlStatus::Enabled
    }
    fn is_failing(&self) -> bool {
        *self == ControlStatus::Disabled
    }
}

#[derive(Debug, Serialize)]
pub struct AccessControlDetail {
    pub status: ControlStatus,
    pub detail: String,
    pub mode: Option<String>,
    pub oidc_issuer: Option<String>,
    pub teams: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct SnapshotInventory {
    pub total: usize,
    pub encrypted: usize,
    pub unencrypted: usize,
    pub encryption_coverage_pct: u8,
    pub total_bytes: u64,
    pub teams: Vec<String>,
    pub oldest_modified: Option<String>,
    pub newest_modified: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditSummary {
    pub log_path: Option<String>,
    pub reachable: bool,
    pub event_count: usize,
    pub earliest: Option<String>,
    pub latest: Option<String>,
    pub actions: HashMap<String, usize>,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub controls_passing: usize,
    pub controls_failing: usize,
    pub controls_unconfigured: usize,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(args: ComplianceArgs) -> Result<()> {
    let report = generate(&args).await?;

    match args.format.as_deref().unwrap_or("json") {
        "markdown" | "md" => {
            let md = render_markdown(&report);
            match &args.output {
                Some(path) => fs::write(path, &md).await.context("writing report")?,
                None => print!("{md}"),
            }
        }
        _ => {
            let json = serde_json::to_string_pretty(&report)?;
            match &args.output {
                Some(path) => fs::write(path, &json).await.context("writing report")?,
                None => println!("{json}"),
            }
        }
    }
    Ok(())
}

// ── Report generation ─────────────────────────────────────────────────────────

async fn generate(args: &ComplianceArgs) -> Result<ComplianceReport> {
    let snapshots = scan_snapshots(&args.snapshot_dir).await?;
    let audit = scan_audit_log(args.audit_log.as_deref()).await;

    let encryption = eval_encryption(&snapshots, &args.key);
    let access_control = eval_access_control(
        args.tokens_file.as_deref(),
        args.oidc_issuer.as_deref(),
        args.token.as_deref(),
    );
    let transport = eval_transport(args.tls_cert.as_deref());
    let audit_ctrl = eval_audit_control(&audit);
    let retention = eval_retention(args.max_age.as_deref(), args.max_size.as_deref());
    let isolation = eval_isolation(&snapshots.teams);

    let controls_passing = [
        encryption.status.is_passing(),
        access_control.status.is_passing(),
        transport.status.is_passing(),
        audit_ctrl.status.is_passing(),
        retention.status.is_passing(),
        isolation.status.is_passing(),
    ]
    .into_iter()
    .filter(|&b| b)
    .count();

    let controls_failing = [
        encryption.status.is_failing(),
        access_control.status.is_failing(),
        transport.status.is_failing(),
        audit_ctrl.status.is_failing(),
        retention.status.is_failing(),
        isolation.status.is_failing(),
    ]
    .into_iter()
    .filter(|&b| b)
    .count();

    let controls_unconfigured = 6 - controls_passing - controls_failing;

    Ok(ComplianceReport {
        generated_at: chrono::Utc::now().to_rfc3339(),
        rewind_version: env!("CARGO_PKG_VERSION"),
        controls: Controls {
            encryption_at_rest: encryption,
            access_control,
            transport_security: transport,
            audit_log: audit_ctrl,
            retention_policy: retention,
            data_isolation: isolation,
        },
        snapshots,
        audit,
        summary: Summary {
            controls_passing,
            controls_failing,
            controls_unconfigured,
        },
    })
}

// ── Snapshot scanning ─────────────────────────────────────────────────────────

struct SnapStats {
    total: usize,
    encrypted: usize,
    total_bytes: u64,
    teams: Vec<String>,
    oldest: Option<std::time::SystemTime>,
    newest: Option<std::time::SystemTime>,
}

async fn scan_snapshots(dir: &Path) -> Result<SnapshotInventory> {
    let stats = scan_dir(dir).await?;
    let unencrypted = stats.total - stats.encrypted;
    let pct = stats
        .encrypted
        .checked_mul(100)
        .and_then(|n| n.checked_div(stats.total))
        .unwrap_or(100) as u8;

    fn fmt_systime(t: std::time::SystemTime) -> String {
        let secs = t
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        chrono::DateTime::<chrono::Utc>::from(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
            .to_rfc3339()
    }

    Ok(SnapshotInventory {
        total: stats.total,
        encrypted: stats.encrypted,
        unencrypted,
        encryption_coverage_pct: pct,
        total_bytes: stats.total_bytes,
        teams: stats.teams,
        oldest_modified: stats.oldest.map(fmt_systime),
        newest_modified: stats.newest.map(fmt_systime),
    })
}

async fn scan_dir(dir: &Path) -> Result<SnapStats> {
    let mut total = 0usize;
    let mut encrypted = 0usize;
    let mut total_bytes = 0u64;
    let mut teams: Vec<String> = Vec::new();
    let mut oldest: Option<std::time::SystemTime> = None;
    let mut newest: Option<std::time::SystemTime> = None;

    let mut root_entries = match fs::read_dir(dir).await {
        Ok(d) => d,
        Err(_) => return Ok(SnapStats { total, encrypted, total_bytes, teams, oldest, newest }),
    };

    // Support both flat layout (dir/*.rwd) and per-team layout (dir/team/*.rwd)
    while let Ok(Some(entry)) = root_entries.next_entry().await {
        let ft = match entry.file_type().await {
            Ok(f) => f,
            Err(_) => continue,
        };
        if ft.is_dir() {
            let team = entry.file_name().to_string_lossy().to_string();
            teams.push(team);
            scan_rwd_files(
                &entry.path(),
                &mut total,
                &mut encrypted,
                &mut total_bytes,
                &mut oldest,
                &mut newest,
            )
            .await;
        } else if entry.file_name().to_string_lossy().ends_with(".rwd") {
            count_rwd_file(
                &entry.path(),
                &mut total,
                &mut encrypted,
                &mut total_bytes,
                &mut oldest,
                &mut newest,
            )
            .await;
        }
    }

    teams.sort();
    Ok(SnapStats { total, encrypted, total_bytes, teams, oldest, newest })
}

async fn scan_rwd_files(
    dir: &Path,
    total: &mut usize,
    encrypted: &mut usize,
    bytes: &mut u64,
    oldest: &mut Option<std::time::SystemTime>,
    newest: &mut Option<std::time::SystemTime>,
) {
    let mut entries = match fs::read_dir(dir).await {
        Ok(d) => d,
        Err(_) => return,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if entry.file_name().to_string_lossy().ends_with(".rwd") {
            count_rwd_file(&entry.path(), total, encrypted, bytes, oldest, newest).await;
        }
    }
}

async fn count_rwd_file(
    path: &Path,
    total: &mut usize,
    encrypted: &mut usize,
    bytes: &mut u64,
    oldest: &mut Option<std::time::SystemTime>,
    newest: &mut Option<std::time::SystemTime>,
) {
    *total += 1;
    if let Ok(meta) = fs::metadata(path).await {
        *bytes += meta.len();
        if let Ok(modified) = meta.modified() {
            match oldest {
                None => *oldest = Some(modified),
                Some(o) if modified < *o => *oldest = Some(modified),
                _ => {}
            }
            match newest {
                None => *newest = Some(modified),
                Some(n) if modified > *n => *newest = Some(modified),
                _ => {}
            }
        }
    }
    // Check age encryption magic in first 18 bytes.
    if let Ok(mut f) = tokio::fs::File::open(path).await {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 18];
        if f.read_exact(&mut buf).await.is_ok() && crypto::is_encrypted(&buf) {
            *encrypted += 1;
        }
    }
}

// ── Audit log scanning ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AuditLine {
    ts: Option<String>,
    action: Option<String>,
}

async fn scan_audit_log(path: Option<&Path>) -> AuditSummary {
    let log_path = path
        .map(|p| p.to_path_buf())
        .or_else(|| {
            std::env::var("REWIND_AUDIT_LOG")
                .ok()
                .map(PathBuf::from)
        })
        .or_else(|| {
            let default = PathBuf::from("/var/log/rewind/audit.log");
            if default.exists() { Some(default) } else { None }
        });

    let Some(ref lp) = log_path else {
        return AuditSummary {
            log_path: None,
            reachable: false,
            event_count: 0,
            earliest: None,
            latest: None,
            actions: HashMap::new(),
        };
    };

    let content = match fs::read_to_string(lp).await {
        Ok(c) => c,
        Err(_) => {
            return AuditSummary {
                log_path: Some(lp.display().to_string()),
                reachable: false,
                event_count: 0,
                earliest: None,
                latest: None,
                actions: HashMap::new(),
            };
        }
    };

    let mut event_count = 0usize;
    let mut earliest: Option<String> = None;
    let mut latest: Option<String> = None;
    let mut actions: HashMap<String, usize> = HashMap::new();

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(al) = serde_json::from_str::<AuditLine>(line) {
            event_count += 1;
            if let Some(action) = al.action {
                *actions.entry(action).or_insert(0) += 1;
            }
            if let Some(ts) = al.ts {
                match &earliest {
                    None => earliest = Some(ts.clone()),
                    Some(e) if ts < *e => earliest = Some(ts.clone()),
                    _ => {}
                }
                match &latest {
                    None => latest = Some(ts.clone()),
                    Some(l) if ts > *l => latest = Some(ts.clone()),
                    _ => {}
                }
            }
        }
    }

    AuditSummary {
        log_path: Some(lp.display().to_string()),
        reachable: true,
        event_count,
        earliest,
        latest,
        actions,
    }
}

// ── Control evaluators ────────────────────────────────────────────────────────

fn eval_encryption(inv: &SnapshotInventory, key: &Option<String>) -> Control {
    let key_configured = key.is_some()
        || std::env::var("REWIND_SNAPSHOT_KEY").is_ok();

    if inv.total == 0 {
        return Control {
            status: if key_configured {
                ControlStatus::Enabled
            } else {
                ControlStatus::Unconfigured
            },
            detail: "No snapshots on disk yet".to_string(),
        };
    }

    if inv.encrypted == inv.total {
        Control {
            status: ControlStatus::Enabled,
            detail: format!(
                "100% of {} snapshots encrypted (age/AES-256-GCM)",
                inv.total
            ),
        }
    } else if inv.encrypted == 0 {
        Control {
            status: ControlStatus::Disabled,
            detail: format!("None of {} snapshots are encrypted", inv.total),
        }
    } else {
        Control {
            status: ControlStatus::Disabled,
            detail: format!(
                "{}/{} snapshots encrypted ({:.0}%) — mixed state",
                inv.encrypted,
                inv.total,
                inv.encryption_coverage_pct
            ),
        }
    }
}

fn eval_access_control(
    tokens_file: Option<&Path>,
    oidc_issuer: Option<&str>,
    token: Option<&str>,
) -> AccessControlDetail {
    if let Some(issuer) = oidc_issuer {
        return AccessControlDetail {
            status: ControlStatus::Enabled,
            detail: format!("OIDC JWT validation (issuer: {issuer})"),
            mode: Some("oidc".to_string()),
            oidc_issuer: Some(issuer.to_string()),
            teams: None,
        };
    }
    if let Some(tf) = tokens_file {
        let teams = std::fs::read_to_string(tf)
            .ok()
            .and_then(|s| serde_json::from_str::<HashMap<String, String>>(&s).ok())
            .map(|m| m.values().collect::<std::collections::HashSet<_>>().len());
        return AccessControlDetail {
            status: ControlStatus::Enabled,
            detail: format!(
                "RBAC token registry ({} teams)",
                teams.unwrap_or(0)
            ),
            mode: Some("rbac".to_string()),
            oidc_issuer: None,
            teams,
        };
    }
    if token.is_some() {
        return AccessControlDetail {
            status: ControlStatus::Enabled,
            detail: "Single shared Bearer token".to_string(),
            mode: Some("single-token".to_string()),
            oidc_issuer: None,
            teams: Some(1),
        };
    }
    AccessControlDetail {
        status: ControlStatus::Disabled,
        detail: "No authentication configured (open server)".to_string(),
        mode: None,
        oidc_issuer: None,
        teams: None,
    }
}

fn eval_transport(tls_cert: Option<&Path>) -> Control {
    match tls_cert {
        Some(p) if p.exists() => Control {
            status: ControlStatus::Enabled,
            detail: format!("TLS certificate: {}", p.display()),
        },
        Some(p) => Control {
            status: ControlStatus::Disabled,
            detail: format!("TLS cert path configured but file not found: {}", p.display()),
        },
        None => Control {
            status: ControlStatus::Unconfigured,
            detail: "No TLS certificate configured (plaintext HTTP)".to_string(),
        },
    }
}

fn eval_audit_control(audit: &AuditSummary) -> Control {
    if !audit.reachable {
        return Control {
            status: ControlStatus::Unconfigured,
            detail: audit
                .log_path
                .as_deref()
                .map(|p| format!("Audit log not found at {p}"))
                .unwrap_or_else(|| "No audit log configured".to_string()),
        };
    }
    Control {
        status: ControlStatus::Enabled,
        detail: format!(
            "{} events recorded; time range {} → {}",
            audit.event_count,
            audit.earliest.as_deref().unwrap_or("?"),
            audit.latest.as_deref().unwrap_or("?"),
        ),
    }
}

fn eval_retention(max_age: Option<&str>, max_size: Option<&str>) -> Control {
    match (max_age, max_size) {
        (None, None) => Control {
            status: ControlStatus::Unconfigured,
            detail: "No retention policy configured — snapshots accumulate indefinitely".to_string(),
        },
        (age, size) => Control {
            status: ControlStatus::Enabled,
            detail: format!(
                "max-age={} max-size={}",
                age.unwrap_or("unlimited"),
                size.unwrap_or("unlimited"),
            ),
        },
    }
}

fn eval_isolation(teams: &[String]) -> Control {
    if teams.is_empty() {
        Control {
            status: ControlStatus::Unconfigured,
            detail: "No per-team subdirectories found".to_string(),
        }
    } else {
        Control {
            status: ControlStatus::Enabled,
            detail: format!(
                "Per-team subdirectory isolation ({} teams: {})",
                teams.len(),
                teams.join(", ")
            ),
        }
    }
}

// ── Markdown renderer ─────────────────────────────────────────────────────────

fn render_markdown(r: &ComplianceReport) -> String {
    let mut md = String::new();
    md.push_str("# rewind Compliance Report\n\n");
    md.push_str(&format!("**Generated:** {}  \n", r.generated_at));
    md.push_str(&format!("**rewind version:** {}  \n\n", r.rewind_version));

    md.push_str("## Summary\n\n");
    md.push_str(&format!(
        "| Controls passing | Controls failing | Unconfigured |\n|---|---|---|\n| {} | {} | {} |\n\n",
        r.summary.controls_passing,
        r.summary.controls_failing,
        r.summary.controls_unconfigured,
    ));

    md.push_str("## Controls\n\n");
    md.push_str("| Control | Status | Detail |\n|---|---|---|\n");
    md.push_str(&ctrl_row("Encryption at rest", &r.controls.encryption_at_rest));
    md.push_str(&format!(
        "| Access control | {} | {} |\n",
        status_icon(&r.controls.access_control.status),
        r.controls.access_control.detail,
    ));
    md.push_str(&ctrl_row("Transport security", &r.controls.transport_security));
    md.push_str(&ctrl_row("Audit log", &r.controls.audit_log));
    md.push_str(&ctrl_row("Retention policy", &r.controls.retention_policy));
    md.push_str(&ctrl_row("Data isolation", &r.controls.data_isolation));
    md.push('\n');

    md.push_str("## Snapshot inventory\n\n");
    md.push_str(&format!("- **Total:** {}\n", r.snapshots.total));
    md.push_str(&format!(
        "- **Encrypted:** {} / {} ({:.0}%)\n",
        r.snapshots.encrypted,
        r.snapshots.total,
        r.snapshots.encryption_coverage_pct,
    ));
    md.push_str(&format!("- **Total size:** {} bytes\n", r.snapshots.total_bytes));
    if !r.snapshots.teams.is_empty() {
        md.push_str(&format!("- **Teams:** {}\n", r.snapshots.teams.join(", ")));
    }
    if let Some(oldest) = &r.snapshots.oldest_modified {
        md.push_str(&format!("- **Oldest:** {oldest}\n"));
    }
    if let Some(newest) = &r.snapshots.newest_modified {
        md.push_str(&format!("- **Newest:** {newest}\n"));
    }
    md.push('\n');

    if r.audit.reachable {
        md.push_str("## Audit log\n\n");
        md.push_str(&format!("- **Path:** {}\n", r.audit.log_path.as_deref().unwrap_or("?")));
        md.push_str(&format!("- **Events:** {}\n", r.audit.event_count));
        if let (Some(e), Some(l)) = (&r.audit.earliest, &r.audit.latest) {
            md.push_str(&format!("- **Range:** {e} → {l}\n"));
        }
        if !r.audit.actions.is_empty() {
            md.push_str("- **Action breakdown:**\n");
            let mut actions: Vec<_> = r.audit.actions.iter().collect();
            actions.sort_by_key(|(k, _)| k.as_str());
            for (action, count) in actions {
                md.push_str(&format!("  - `{action}`: {count}\n"));
            }
        }
    }

    md
}

fn ctrl_row(name: &str, c: &Control) -> String {
    format!("| {} | {} | {} |\n", name, status_icon(&c.status), c.detail)
}

fn status_icon(s: &ControlStatus) -> &'static str {
    match s {
        ControlStatus::Enabled => "✅ Enabled",
        ControlStatus::Disabled => "❌ Disabled",
        ControlStatus::Unconfigured => "⚠️ Unconfigured",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_disabled_when_no_snapshots_no_key() {
        let inv = SnapshotInventory {
            total: 0,
            encrypted: 0,
            unencrypted: 0,
            encryption_coverage_pct: 100,
            total_bytes: 0,
            teams: vec![],
            oldest_modified: None,
            newest_modified: None,
        };
        std::env::remove_var("REWIND_SNAPSHOT_KEY");
        let ctrl = eval_encryption(&inv, &None);
        assert_eq!(ctrl.status, ControlStatus::Unconfigured);
    }

    #[test]
    fn encryption_enabled_when_all_encrypted() {
        let inv = SnapshotInventory {
            total: 5,
            encrypted: 5,
            unencrypted: 0,
            encryption_coverage_pct: 100,
            total_bytes: 1000,
            teams: vec![],
            oldest_modified: None,
            newest_modified: None,
        };
        let ctrl = eval_encryption(&inv, &Some("key".to_string()));
        assert_eq!(ctrl.status, ControlStatus::Enabled);
    }

    #[test]
    fn encryption_disabled_when_none_encrypted() {
        let inv = SnapshotInventory {
            total: 3,
            encrypted: 0,
            unencrypted: 3,
            encryption_coverage_pct: 0,
            total_bytes: 500,
            teams: vec![],
            oldest_modified: None,
            newest_modified: None,
        };
        let ctrl = eval_encryption(&inv, &None);
        assert_eq!(ctrl.status, ControlStatus::Disabled);
    }

    #[test]
    fn access_control_oidc_takes_precedence() {
        let ctrl = eval_access_control(
            Some(Path::new("/etc/tokens.json")),
            Some("https://accounts.google.com"),
            None,
        );
        assert_eq!(ctrl.status, ControlStatus::Enabled);
        assert_eq!(ctrl.mode.as_deref(), Some("oidc"));
    }

    #[test]
    fn access_control_disabled_when_nothing_configured() {
        let ctrl = eval_access_control(None, None, None);
        assert_eq!(ctrl.status, ControlStatus::Disabled);
    }

    #[test]
    fn transport_unconfigured_without_cert() {
        let ctrl = eval_transport(None);
        assert_eq!(ctrl.status, ControlStatus::Unconfigured);
    }

    #[test]
    fn retention_unconfigured_without_limits() {
        let ctrl = eval_retention(None, None);
        assert_eq!(ctrl.status, ControlStatus::Unconfigured);
    }

    #[test]
    fn retention_enabled_with_age_only() {
        let ctrl = eval_retention(Some("30d"), None);
        assert_eq!(ctrl.status, ControlStatus::Enabled);
        assert!(ctrl.detail.contains("30d"));
    }

    #[test]
    fn isolation_unconfigured_with_no_teams() {
        let ctrl = eval_isolation(&[]);
        assert_eq!(ctrl.status, ControlStatus::Unconfigured);
    }

    #[test]
    fn isolation_enabled_with_teams() {
        let ctrl = eval_isolation(&["api".to_string(), "payments".to_string()]);
        assert_eq!(ctrl.status, ControlStatus::Enabled);
    }

    #[test]
    fn audit_unconfigured_when_not_reachable() {
        let audit = AuditSummary {
            log_path: None,
            reachable: false,
            event_count: 0,
            earliest: None,
            latest: None,
            actions: HashMap::new(),
        };
        let ctrl = eval_audit_control(&audit);
        assert_eq!(ctrl.status, ControlStatus::Unconfigured);
    }

    #[test]
    fn markdown_contains_summary_table() {
        let report = ComplianceReport {
            generated_at: "2026-04-22T00:00:00Z".to_string(),
            rewind_version: "0.1.0",
            controls: Controls {
                encryption_at_rest: Control {
                    status: ControlStatus::Enabled,
                    detail: "ok".to_string(),
                },
                access_control: AccessControlDetail {
                    status: ControlStatus::Enabled,
                    detail: "rbac".to_string(),
                    mode: Some("rbac".to_string()),
                    oidc_issuer: None,
                    teams: Some(2),
                },
                transport_security: Control {
                    status: ControlStatus::Unconfigured,
                    detail: "no tls".to_string(),
                },
                audit_log: Control {
                    status: ControlStatus::Enabled,
                    detail: "100 events".to_string(),
                },
                retention_policy: Control {
                    status: ControlStatus::Enabled,
                    detail: "30d".to_string(),
                },
                data_isolation: Control {
                    status: ControlStatus::Enabled,
                    detail: "2 teams".to_string(),
                },
            },
            snapshots: SnapshotInventory {
                total: 10,
                encrypted: 10,
                unencrypted: 0,
                encryption_coverage_pct: 100,
                total_bytes: 9999,
                teams: vec!["api".to_string()],
                oldest_modified: None,
                newest_modified: None,
            },
            audit: AuditSummary {
                log_path: None,
                reachable: false,
                event_count: 0,
                earliest: None,
                latest: None,
                actions: HashMap::new(),
            },
            summary: Summary {
                controls_passing: 5,
                controls_failing: 0,
                controls_unconfigured: 1,
            },
        };
        let md = render_markdown(&report);
        assert!(md.contains("## Summary"));
        assert!(md.contains("| 5 | 0 | 1 |"));
        assert!(md.contains("## Controls"));
    }
}
