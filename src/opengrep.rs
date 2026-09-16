use std::{
    collections::{HashMap, HashSet},
    error::Error as StdError,
    ffi::OsString,
    fs::{self, File},
    io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use color_eyre::{
    eyre::{bail, ensure, Context},
    Result,
};
use reqwest::{blocking::Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::{tempdir, tempfile, TempDir};
use tracing::{info, warn};
use walkdir::WalkDir;
use xxhash_rust::xxh3::Xxh3;

use crate::{
    app_config::APP_CONFIG,
    client::{
        build_api_http_client, build_download_http_client, download_distribution_with_timeout,
        fetch_opengrep_jobs, fetch_opengrep_rules, send_opengrep_result, Job, OpenGrepFinding,
        OpenGrepRulesResponse, OpenGrepScanResult, SubmitOpenGrepResultsError,
        SubmitOpenGrepResultsSuccess,
    },
    utils::create_inspector_url,
};

const API_ORIGINS: [&str; 2] = [
    "https://dragonfly-staging.vipyrsec.com",
    "https://dragonfly.vipyrsec.com",
];
const MAX_FINDINGS: usize = 500;
const MAX_OPENGREP_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
const SCAN_DEADLINE: Duration = Duration::from_secs(60);
const RULE_INSPECTION_DEADLINE: Duration = Duration::from_secs(10);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Deserialize)]
struct Position {
    line: u64,
}

#[derive(Debug, Deserialize)]
struct FindingMetadata {
    evidence: String,
    confidence: String,
    execution_context: String,
}

#[derive(Debug, Deserialize)]
struct FindingExtra {
    message: String,
    severity: String,
    metadata: FindingMetadata,
}

#[derive(Debug, Deserialize)]
struct RawFinding {
    check_id: String,
    path: PathBuf,
    start: Position,
    end: Position,
    extra: FindingExtra,
}

#[derive(Debug, Deserialize)]
struct OpenGrepDocument {
    #[serde(default)]
    paths: ScannedPaths,
    results: Vec<RawFinding>,
    #[serde(default)]
    errors: Vec<Value>,
    #[serde(default)]
    skipped_rules: Vec<Value>,
}

#[derive(Debug, Default, Deserialize)]
struct ScannedPaths {
    #[serde(default)]
    scanned: Vec<PathBuf>,
}

#[derive(Debug)]
struct ScanTimeout(&'static str);

impl std::fmt::Display for ScanTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl StdError for ScanTimeout {}

#[derive(Debug)]
struct OpenGrepRun {
    findings: Vec<OpenGrepFinding>,
    warnings: Vec<String>,
    scanned_paths: HashSet<String>,
}

#[derive(Debug)]
struct ScanJobOutcome {
    findings: Vec<OpenGrepFinding>,
    partial_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FileIdentity {
    digest: u128,
    size: u64,
    extension: Option<OsString>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TargetAlias {
    target_id: u64,
    distribution_index: usize,
    path: String,
}

#[derive(Debug)]
enum PlannedTarget {
    Existing(u64),
    Pending(usize),
}

#[derive(Debug)]
struct PlannedAlias {
    target: PlannedTarget,
    path: String,
}

#[derive(Debug)]
struct PendingTarget {
    identity: FileIdentity,
    source: PathBuf,
}

#[derive(Debug)]
struct DistributionTargetPlan {
    aliases: Vec<PlannedAlias>,
    pending: Vec<PendingTarget>,
}

struct PackageTarget {
    directory: TempDir,
    identities: HashMap<FileIdentity, u64>,
    inspectors: Vec<Url>,
    aliases: BufWriter<File>,
    next_target_id: u64,
    deduplicated_files: usize,
}

impl PackageTarget {
    fn new() -> Result<Self> {
        Ok(Self {
            directory: tempdir()?,
            identities: HashMap::new(),
            inspectors: Vec::new(),
            aliases: BufWriter::new(tempfile()?),
            next_target_id: 0,
            deduplicated_files: 0,
        })
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }

    fn is_empty(&self) -> bool {
        self.next_target_id == 0
    }

    fn target_count(&self) -> u64 {
        self.next_target_id
    }

    fn plan_distribution(
        &self,
        source_directory: &Path,
        deadline: Instant,
    ) -> Result<DistributionTargetPlan> {
        let mut paths = Vec::new();
        for entry in WalkDir::new(source_directory).follow_links(false) {
            ensure_scan_time_remaining(deadline)?;
            let entry = entry?;
            if entry.file_type().is_file() {
                paths.push(entry.into_path());
            }
        }
        paths.sort_unstable();

        let mut local_pending = HashMap::new();
        let mut aliases = Vec::new();
        let mut pending = Vec::new();
        for path in paths {
            ensure_scan_time_remaining(deadline)?;
            let file_size = path.metadata()?.len();
            if file_size > APP_CONFIG.max_scan_size {
                continue;
            }
            let relative_path = relative_target_path(&path, source_directory)?;
            let identity = hash_file(&path, file_size, deadline)?;
            let target = if let Some(target_id) = self.identities.get(&identity) {
                PlannedTarget::Existing(*target_id)
            } else if let Some(pending_index) = local_pending.get(&identity) {
                PlannedTarget::Pending(*pending_index)
            } else {
                let pending_index = pending.len();
                local_pending.insert(identity.clone(), pending_index);
                pending.push(PendingTarget {
                    identity,
                    source: path,
                });
                PlannedTarget::Pending(pending_index)
            };
            aliases.push(PlannedAlias {
                target,
                path: relative_path,
            });
        }

        Ok(DistributionTargetPlan { aliases, pending })
    }

    fn commit_distribution(&mut self, plan: DistributionTargetPlan, inspector: Url) -> Result<()> {
        let distribution_index = self.inspectors.len();
        self.inspectors.push(inspector);
        self.deduplicated_files = self
            .deduplicated_files
            .saturating_add(plan.aliases.len().saturating_sub(plan.pending.len()));

        let mut pending_ids = Vec::with_capacity(plan.pending.len());
        for pending in plan.pending {
            let target_id = self.next_target_id;
            self.next_target_id = self
                .next_target_id
                .checked_add(1)
                .ok_or_else(|| color_eyre::eyre::eyre!("OpenGrep target identifier overflowed"))?;
            let destination = self.target_path(target_id, pending.identity.extension.as_deref());
            fs::hard_link(&pending.source, destination)?;
            self.identities.insert(pending.identity, target_id);
            pending_ids.push(target_id);
        }

        for alias in plan.aliases {
            let target_id = match alias.target {
                PlannedTarget::Existing(target_id) => target_id,
                PlannedTarget::Pending(index) => pending_ids[index],
            };
            serde_json::to_writer(
                &mut self.aliases,
                &TargetAlias {
                    target_id,
                    distribution_index,
                    path: alias.path,
                },
            )?;
            self.aliases.write_all(b"\n")?;
        }
        Ok(())
    }

    fn target_path(&self, target_id: u64, extension: Option<&std::ffi::OsStr>) -> PathBuf {
        let mut path = self.path().join(format!("{target_id:016x}"));
        if let Some(extension) = extension {
            path.set_extension(extension);
        }
        path
    }

    fn expand_findings(&mut self, findings: Vec<OpenGrepFinding>) -> Result<Vec<OpenGrepFinding>> {
        let mut findings_by_target: HashMap<u64, Vec<OpenGrepFinding>> = HashMap::new();
        for finding in findings {
            let target_id = target_id_from_path(&finding.path)?;
            findings_by_target
                .entry(target_id)
                .or_default()
                .push(finding);
        }
        if findings_by_target.is_empty() {
            return Ok(Vec::new());
        }

        self.aliases.flush()?;
        self.aliases.seek(SeekFrom::Start(0))?;
        let mut expanded = Vec::new();
        for line in BufReader::new(self.aliases.get_mut()).lines() {
            let alias: TargetAlias = serde_json::from_str(&line?)?;
            let Some(canonical_findings) = findings_by_target.get(&alias.target_id) else {
                continue;
            };
            let inspector = self
                .inspectors
                .get(alias.distribution_index)
                .ok_or_else(|| {
                    color_eyre::eyre::eyre!("finding references an unknown distribution")
                })?;
            ensure!(
                expanded.len().saturating_add(canonical_findings.len()) <= MAX_FINDINGS,
                "OpenGrep produced more than {MAX_FINDINGS} findings"
            );
            for finding in canonical_findings {
                expanded.push(rewrite_finding_location(finding, &alias.path, inspector)?);
            }
        }
        Ok(expanded)
    }
}

fn content_findings(findings: &[OpenGrepFinding]) -> Result<Vec<String>> {
    let mut values = Vec::new();
    for finding in findings {
        let mut finding = finding.clone();
        finding.path.clear();
        finding.inspector_url.clear();
        values.push(serde_json::to_string(&finding)?);
    }
    values.sort_unstable();
    Ok(values)
}

fn target_id_from_path(path: &str) -> Result<u64> {
    let stem = Path::new(path)
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("OpenGrep returned an invalid target path"))?;
    Ok(u64::from_str_radix(stem, 16)?)
}

#[derive(Serialize)]
pub struct ReportedOpenGrepResult {
    #[serde(flatten)]
    pub result: OpenGrepScanResult,
    scan_reuse: crate::reuse_cache::CacheStats,
}

pub struct OpenGrepClient {
    api_client: Client,
    download_client: Client,
    base_url: String,
    binary: PathBuf,
    rules_directory: TempDir,
    content_reuse_safe: bool,
    pub rules_hash: String,
    reuse_cache: crate::reuse_cache::ReuseCache,
}

impl OpenGrepClient {
    /// Build an origin-validated shadow client and load its initial corpus.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin fence, HTTP clients, rule retrieval,
    /// or safe rule materialization fails.
    pub fn new(binary: PathBuf) -> Result<Self> {
        validate_api_origin(&APP_CONFIG.base_url)?;
        let api_client = build_api_http_client(
            &APP_CONFIG.cf_access_client_id,
            &APP_CONFIG.cf_access_client_secret,
        )?;
        let download_client = build_download_http_client()?;
        let response = fetch_opengrep_rules(&api_client, &APP_CONFIG.base_url)?;
        let rules_hash = response.hash.clone();
        let rules_directory = materialize_rules(&response)?;
        let content_reuse_safe = rules_allow_content_reuse(&binary, rules_directory.path())?;
        Ok(Self {
            api_client,
            download_client,
            base_url: APP_CONFIG.base_url.trim_end_matches('/').to_owned(),
            binary,
            rules_directory,
            content_reuse_safe,
            rules_hash,
            reuse_cache: crate::reuse_cache::ReuseCache::new(
                APP_CONFIG.reuse_cache_mode,
                APP_CONFIG.reuse_cache_entries,
                APP_CONFIG.reuse_cache_bytes,
            ),
        })
    }

    /// Replace the local `OpenGrep` corpus from Mainframe.
    ///
    /// # Errors
    ///
    /// Returns an error when retrieval or safe materialization fails.
    pub fn refresh_rules(&mut self) -> Result<()> {
        let response = fetch_opengrep_rules(&self.api_client, &self.base_url)?;
        let rules_directory = materialize_rules(&response)?;
        let content_reuse_safe = rules_allow_content_reuse(&self.binary, rules_directory.path())?;
        self.reuse_cache.clear();
        self.rules_hash = response.hash;
        self.rules_directory = rules_directory;
        self.content_reuse_safe = content_reuse_safe;
        Ok(())
    }

    /// Lease up to `count` `OpenGrep` shadow jobs.
    ///
    /// # Errors
    ///
    /// Returns an HTTP or response-deserialization error.
    pub fn get_jobs(&self, count: usize) -> reqwest::Result<Vec<Job>> {
        fetch_opengrep_jobs(&self.api_client, &self.base_url, count)
    }

    /// Scan one job and convert every failure into a bounded result payload.
    #[must_use]
    pub fn run_job(&self, job: &Job) -> ReportedOpenGrepResult {
        let started_at = Instant::now();
        let mut stats = crate::reuse_cache::CacheStats::new("opengrep", self.reuse_cache.mode);
        let result = self.scan_job(job, &mut stats);
        stats.emit();
        let duration_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let result = match result {
            Ok(outcome) => OpenGrepScanResult::Success(SubmitOpenGrepResultsSuccess {
                name: job.name.clone(),
                version: job.version.clone(),
                attempt: job.attempt,
                assignment_id: job.assignment_id.clone(),
                commit: job.hash.clone(),
                duration_ms,
                findings: outcome.findings,
                partial_reason: outcome.partial_reason,
            }),
            Err(error) => OpenGrepScanResult::Error(SubmitOpenGrepResultsError {
                name: job.name.clone(),
                version: job.version.clone(),
                attempt: job.attempt,
                assignment_id: job.assignment_id.clone(),
                duration_ms,
                reason: truncate(&format!("{error:#}"), 2048),
            }),
        };
        ReportedOpenGrepResult {
            result,
            scan_reuse: stats,
        }
    }

    /// Submit one completed `OpenGrep` shadow result.
    ///
    /// # Errors
    ///
    /// Returns an HTTP or serialization error.
    pub fn submit_result(&self, result: &ReportedOpenGrepResult) -> reqwest::Result<()> {
        send_opengrep_result(&self.api_client, &self.base_url, result)
    }

    fn scan_job(
        &self,
        job: &Job,
        stats: &mut crate::reuse_cache::CacheStats,
    ) -> Result<ScanJobOutcome> {
        ensure!(
            job.hash == self.rules_hash,
            "job rules do not match the loaded rules snapshot"
        );
        if self.content_reuse_safe {
            return self.scan_job_batched(job, stats);
        }
        self.scan_job_by_distribution(job)
    }

    fn scan_job_batched(
        &self,
        job: &Job,
        stats: &mut crate::reuse_cache::CacheStats,
    ) -> Result<ScanJobOutcome> {
        ensure!(
            job.distributions.len() <= APP_CONFIG.max_distributions,
            "package contains {} distributions, exceeding the {}-distribution limit",
            job.distributions.len(),
            APP_CONFIG.max_distributions
        );
        let mut warnings = Vec::new();
        let mut package_target = PackageTarget::new()?;
        let mut prepared_distributions = 0_u32;
        for distribution in &job.distributions {
            let distribution_started_at = Instant::now();
            let download_url: Url = distribution.parse()?;
            let inspector_url = create_inspector_url(&job.name, &job.version, &download_url);
            let directory = match download_distribution_with_timeout(
                &self.download_client,
                download_url,
                Some(SCAN_DEADLINE),
            ) {
                Ok(directory) => directory,
                Err(error) if is_timeout_error(&error) => {
                    warnings.push(format!(
                        "Timed out downloading or extracting distribution {distribution}"
                    ));
                    break;
                }
                Err(error) => return Err(error),
            };
            let distribution_deadline = distribution_started_at + SCAN_DEADLINE;
            let target_plan =
                match package_target.plan_distribution(directory.path(), distribution_deadline) {
                    Ok(plan) => plan,
                    Err(error) if is_timeout_error(&error) => {
                        warnings.push(format!("Timed out preparing distribution {distribution}"));
                        break;
                    }
                    Err(error) => return Err(error),
                };
            package_target.commit_distribution(target_plan, inspector_url)?;
            prepared_distributions = prepared_distributions.saturating_add(1);
        }

        if package_target.deduplicated_files > 0 {
            info!(
                package = %job.name,
                version = %job.version,
                deduplicated_files = package_target.deduplicated_files,
                unique_targets = package_target.target_count(),
                "Prepared deduplicated package target"
            );
        }

        self.scan_prepared_package(
            &mut package_target,
            prepared_distributions,
            warnings,
            job,
            stats,
        )
    }

    fn scan_prepared_package(
        &self,
        package_target: &mut PackageTarget,
        prepared_distributions: u32,
        mut warnings: Vec<String>,
        job: &Job,
        stats: &mut crate::reuse_cache::CacheStats,
    ) -> Result<ScanJobOutcome> {
        let mut findings = Vec::new();
        let mut reused_findings = Vec::new();
        let mut pending = Vec::new();
        for (identity, target_id) in &package_target.identities {
            let path = package_target.target_path(*target_id, identity.extension.as_deref());
            let key = format!(
                "{:032x}:{}:{:?}",
                identity.digest, identity.size, identity.extension
            );
            let cached = self
                .reuse_cache
                .lookup::<Vec<OpenGrepFinding>>(&key, &path, stats);
            if let Some(mut cached) = cached
                .as_ref()
                .filter(|_| self.reuse_cache.should_reuse())
                .cloned()
            {
                let relative = relative_target_path(&path, package_target.path())?;
                for finding in &mut cached {
                    finding.path.clone_from(&relative);
                }
                append_findings(&mut reused_findings, cached)?;
                fs::remove_file(&path)?;
                stats.reused_files += 1;
                stats.reused_bytes += identity.size;
            } else {
                pending.push((key, path, identity.size, cached));
            }
        }
        if !pending.is_empty() {
            stats.engine_files = u64::try_from(pending.len())?;
            stats.engine_bytes = pending.iter().map(|(_, _, size, _)| size).sum();
            let engine_started = Instant::now();
            let package_run =
                self.run_package_target(package_target.path(), prepared_distributions, job);
            stats.engine_us = engine_started.elapsed().as_micros();
            let package_run = package_run?;
            let complete = package_run.warnings.is_empty() && warnings.is_empty();
            let mut by_path: HashMap<String, Vec<OpenGrepFinding>> = HashMap::new();
            for finding in &package_run.findings {
                by_path
                    .entry(finding.path.clone())
                    .or_default()
                    .push(finding.clone());
            }
            append_findings(&mut reused_findings, package_run.findings)?;
            findings = package_target.expand_findings(reused_findings)?;
            if complete {
                for (key, path, _, previous) in pending {
                    let relative = relative_target_path(&path, package_target.path())?;
                    // No finding does not prove a file was scanned. Require engine coverage.
                    if package_run.scanned_paths.contains(&relative) {
                        let current = by_path.remove(&relative).unwrap_or_default();
                        if let Some(previous) = previous {
                            stats.validated_files += 1;
                            if content_findings(&previous)? != content_findings(&current)? {
                                stats.mismatched_files += 1;
                                self.reuse_cache.disable();
                                tracing::error!(
                                    event = "scan_reuse_mismatch",
                                    "Cached OpenGrep results differ from fresh scan"
                                );
                            }
                        }
                        self.reuse_cache.insert(key, &path, &current, stats);
                    }
                }
            }
            warnings.extend(package_run.warnings);
        } else if !package_target.is_empty() {
            findings = package_target.expand_findings(reused_findings)?;
        }
        ensure!(!(stats.reused_files > 0 && self.reuse_cache.is_disabled()),
            "Cross-package cache validation failed; reuse disabled and this job's cached results discarded");
        let partial_reason = (!warnings.is_empty()).then(|| truncate(&warnings.join("; "), 2048));
        Ok(ScanJobOutcome {
            findings,
            partial_reason,
        })
    }

    fn run_package_target(
        &self,
        target: &Path,
        distributions: u32,
        job: &Job,
    ) -> Result<OpenGrepRun> {
        let deadline = SCAN_DEADLINE
            .checked_mul(distributions.max(1))
            .ok_or_else(|| color_eyre::eyre::eyre!("package scan deadline overflowed"))?;
        let inspector = Url::parse("https://opengrep-target.invalid/")?;
        run_opengrep(
            &self.binary,
            self.rules_directory.path(),
            target,
            &inspector,
            deadline,
        )
        .or_else(|error| {
            if is_timeout_error(&error) {
                warn!(package = %job.name, version = %job.version,
                        "Package OpenGrep scan timed out; retrying bounded target groups");
                run_opengrep_in_groups(
                    &self.binary,
                    self.rules_directory.path(),
                    target,
                    &inspector,
                )
            } else {
                Err(error)
            }
        })
    }

    fn scan_job_by_distribution(&self, job: &Job) -> Result<ScanJobOutcome> {
        ensure!(
            job.distributions.len() <= APP_CONFIG.max_distributions,
            "package contains {} distributions, exceeding the {}-distribution limit",
            job.distributions.len(),
            APP_CONFIG.max_distributions
        );
        let mut findings = Vec::new();
        let mut warnings = Vec::new();
        for distribution in &job.distributions {
            let distribution_started_at = Instant::now();
            let download_url: Url = distribution.parse()?;
            let inspector_url = create_inspector_url(&job.name, &job.version, &download_url);
            let directory = match download_distribution_with_timeout(
                &self.download_client,
                download_url,
                Some(SCAN_DEADLINE),
            ) {
                Ok(directory) => directory,
                Err(error) if is_timeout_error(&error) => {
                    warnings.push(format!(
                        "Timed out downloading or extracting distribution {distribution}"
                    ));
                    break;
                }
                Err(error) => return Err(error),
            };
            let Some(remaining) = SCAN_DEADLINE.checked_sub(distribution_started_at.elapsed())
            else {
                warnings.push(format!("Timed out preparing distribution {distribution}"));
                break;
            };
            let distribution_run = match run_opengrep(
                &self.binary,
                self.rules_directory.path(),
                directory.path(),
                &inspector_url,
                remaining,
            ) {
                Ok(run) => run,
                Err(error) if is_timeout_error(&error) => {
                    warnings.push(format!("Timed out scanning distribution {distribution}"));
                    break;
                }
                Err(error) => return Err(error),
            };
            append_findings(&mut findings, distribution_run.findings)?;
            warnings.extend(distribution_run.warnings);
        }
        let partial_reason = (!warnings.is_empty()).then(|| truncate(&warnings.join("; "), 2048));
        Ok(ScanJobOutcome {
            findings,
            partial_reason,
        })
    }
}

fn run_opengrep_in_groups(
    binary: &Path,
    rules_directory: &Path,
    target_directory: &Path,
    inspector_base: &Url,
) -> Result<OpenGrepRun> {
    ensure!(
        APP_CONFIG.max_archive_entries > 0,
        "OpenGrep fallback group size must be positive"
    );
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    let mut group = tempdir()?;
    let mut group_size = 0_usize;

    for entry in fs::read_dir(target_directory)? {
        let entry = entry?;
        ensure!(
            entry.file_type()?.is_file(),
            "package target contains a non-file entry"
        );
        fs::hard_link(entry.path(), group.path().join(entry.file_name()))?;
        group_size = group_size.saturating_add(1);
        if group_size < APP_CONFIG.max_archive_entries {
            continue;
        }
        if !run_opengrep_group(
            binary,
            rules_directory,
            &group,
            inspector_base,
            &mut findings,
            &mut warnings,
        )? {
            return Ok(OpenGrepRun {
                findings,
                warnings,
                scanned_paths: HashSet::new(),
            });
        }
        group = tempdir()?;
        group_size = 0;
    }

    if group_size > 0 {
        run_opengrep_group(
            binary,
            rules_directory,
            &group,
            inspector_base,
            &mut findings,
            &mut warnings,
        )?;
    }
    Ok(OpenGrepRun {
        findings,
        warnings,
        scanned_paths: HashSet::new(),
    })
}

fn run_opengrep_group(
    binary: &Path,
    rules_directory: &Path,
    group: &TempDir,
    inspector_base: &Url,
    findings: &mut Vec<OpenGrepFinding>,
    warnings: &mut Vec<String>,
) -> Result<bool> {
    match run_opengrep(
        binary,
        rules_directory,
        group.path(),
        inspector_base,
        SCAN_DEADLINE,
    ) {
        Ok(run) => {
            append_findings(findings, run.findings)?;
            warnings.extend(run.warnings);
            Ok(true)
        }
        Err(error) if is_timeout_error(&error) => {
            warnings.push("Timed out scanning a fallback package target group".to_owned());
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn append_findings(
    findings: &mut Vec<OpenGrepFinding>,
    additional: Vec<OpenGrepFinding>,
) -> Result<()> {
    ensure!(
        findings.len().saturating_add(additional.len()) <= MAX_FINDINGS,
        "OpenGrep produced more than {MAX_FINDINGS} findings"
    );
    findings.extend(additional);
    Ok(())
}

/// Require a supported Dragonfly API origin without paths, credentials, or queries.
///
/// # Errors
///
/// Returns an error when the URL is invalid or is not a supported Dragonfly origin.
pub fn validate_api_origin(base_url: &str) -> Result<()> {
    let parsed = Url::parse(base_url)?;

    ensure!(
        API_ORIGINS.contains(&parsed.origin().ascii_serialization().as_str())
            && parsed.path().trim_end_matches('/').is_empty()
            && parsed.query().is_none()
            && parsed.fragment().is_none()
            && parsed.username().is_empty()
            && parsed.password().is_none(),
        "OpenGrep worker requires a supported Dragonfly API origin"
    );
    Ok(())
}

fn materialize_rules(response: &OpenGrepRulesResponse) -> Result<TempDir> {
    ensure!(!response.rules.is_empty(), "OpenGrep rule corpus is empty");
    let directory = tempdir()?;
    for (relative_path, contents) in &response.rules {
        let relative_path = safe_relative_path(relative_path)?;
        let destination = directory.path().join(relative_path);
        let parent = destination
            .parent()
            .ok_or_else(|| color_eyre::eyre::eyre!("OpenGrep rule path has no parent"))?;
        fs::create_dir_all(parent)?;
        fs::write(destination, contents)?;
    }
    Ok(directory)
}

fn rules_allow_content_reuse(binary: &Path, rules_directory: &Path) -> Result<bool> {
    let mut stdout_file = tempfile()?;
    let mut stderr_file = tempfile()?;
    let mut child = Command::new(binary)
        .args([
            "show",
            "dump-config",
            rules_directory
                .to_str()
                .ok_or_else(|| color_eyre::eyre::eyre!("rule path is not UTF-8"))?,
        ])
        .env("HOME", "/tmp")
        .env("XDG_CACHE_HOME", "/tmp")
        .env("OPENGREP_ENABLE_VERSION_CHECK", "0")
        .stdout(Stdio::from(stdout_file.try_clone()?))
        .stderr(Stdio::from(stderr_file.try_clone()?))
        .spawn()
        .wrap_err("failed to inspect OpenGrep rules")?;
    let status = wait_for_child(
        &mut child,
        &stdout_file,
        &stderr_file,
        RULE_INSPECTION_DEADLINE,
        "OpenGrep rule inspection exceeded its deadline",
    )?;
    let stderr = read_bounded(&mut stderr_file)?;
    ensure!(
        status.success(),
        "OpenGrep rule inspection exited with {status}: {}",
        truncate(&stderr, 1024)
    );
    let parsed_rules = read_bounded(&mut stdout_file)?;
    let rule_count = parsed_rules.matches("Rule.id = (").count();
    ensure!(rule_count > 0, "OpenGrep rule inspection returned no rules");
    let normalized = parsed_rules
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    // Only plain single-file SAST search/taint rules are eligible. Options can
    // enable interfile analysis; dependencies, validators and other modes can
    // depend on package context even when paths are unrestricted.
    Ok(rule_count == normalized.matches("paths = None;").count()
        && rule_count == normalized.matches("options = None;").count()
        && rule_count == normalized.matches("dependency_formula = None;").count()
        && rule_count == normalized.matches("validators = None;").count()
        && rule_count == normalized.matches("product = `SAST;").count()
        && rule_count
            == normalized.matches("mode = `Search").count()
                + normalized.matches("mode = `Taint").count())
}

fn safe_relative_path(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    ensure!(!path.as_os_str().is_empty(), "path must not be empty");
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "path must contain only normal relative components"
    );
    Ok(path.to_path_buf())
}

fn run_opengrep(
    binary: &Path,
    rules_directory: &Path,
    target_directory: &Path,
    inspector_base: &Url,
    deadline: Duration,
) -> Result<OpenGrepRun> {
    let mut stdout_file = tempfile()?;
    let mut stderr_file = tempfile()?;
    let mut child = Command::new(binary)
        .args([
            "scan",
            "--config",
            rules_directory
                .to_str()
                .ok_or_else(|| color_eyre::eyre::eyre!("rule path is not UTF-8"))?,
            "--json",
            "--no-git-ignore",
            "--jobs",
            "1",
            "--timeout",
            "5",
            "--max-target-bytes",
            &APP_CONFIG.max_scan_size.to_string(),
            target_directory
                .to_str()
                .ok_or_else(|| color_eyre::eyre::eyre!("target path is not UTF-8"))?,
        ])
        .env("HOME", "/tmp")
        .env("XDG_CACHE_HOME", "/tmp")
        .env("OPENGREP_ENABLE_VERSION_CHECK", "0")
        .stdout(Stdio::from(stdout_file.try_clone()?))
        .stderr(Stdio::from(stderr_file.try_clone()?))
        .spawn()
        .wrap_err("failed to start OpenGrep")?;

    let status = wait_for_child(
        &mut child,
        &stdout_file,
        &stderr_file,
        deadline,
        "OpenGrep exceeded the scan deadline",
    )?;

    let stderr = read_bounded(&mut stderr_file)?;
    ensure!(
        status.success(),
        "OpenGrep exited with {status}: {}",
        truncate(&stderr, 1024)
    );
    let stdout = read_bounded(&mut stdout_file)?;
    let document: OpenGrepDocument =
        serde_json::from_str(&stdout).wrap_err("OpenGrep returned invalid JSON")?;
    let unexpected_errors: Vec<&Value> = document
        .errors
        .iter()
        .filter(|error| !is_recoverable_scan_warning(error))
        .collect();
    ensure!(
        unexpected_errors.is_empty(),
        "OpenGrep reported scan errors: {}",
        serde_json::to_string(&unexpected_errors)?
    );
    let warnings = document
        .errors
        .iter()
        .filter(|error| is_recoverable_scan_warning(error))
        .map(describe_recoverable_scan_warning)
        .collect::<Vec<_>>();
    if !warnings.is_empty() {
        warn!(
            recoverable_scan_warnings = warnings.len(),
            "OpenGrep reported recoverable scan warnings; preserving valid findings"
        );
    }
    ensure!(
        document.skipped_rules.is_empty(),
        "OpenGrep skipped rules: {}",
        serde_json::to_string(&document.skipped_rules)?
    );

    let scanned_paths = document
        .paths
        .scanned
        .iter()
        .map(|path| relative_target_path(path, target_directory))
        .collect::<Result<HashSet<_>>>()?;
    let findings = document
        .results
        .into_iter()
        .map(|finding| normalize_finding(finding, target_directory, inspector_base))
        .collect::<Result<Vec<_>>>()?;
    Ok(OpenGrepRun {
        findings,
        warnings,
        scanned_paths,
    })
}

fn wait_for_child(
    child: &mut Child,
    stdout_file: &File,
    stderr_file: &File,
    deadline: Duration,
    timeout_message: &'static str,
) -> Result<ExitStatus> {
    let started_at = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        let output_too_large = stdout_file.metadata()?.len() > MAX_OPENGREP_OUTPUT_BYTES
            || stderr_file.metadata()?.len() > MAX_OPENGREP_OUTPUT_BYTES;
        if output_too_large {
            child.kill()?;
            child.wait()?;
            bail!("OpenGrep output exceeded {MAX_OPENGREP_OUTPUT_BYTES} bytes");
        }
        if started_at.elapsed() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(ScanTimeout(timeout_message).into());
        }
        thread::sleep(CHILD_POLL_INTERVAL);
    }
}

fn is_recoverable_scan_warning(error: &Value) -> bool {
    if error.get("level").and_then(Value::as_str) != Some("warn") {
        return false;
    }
    error.get("type").and_then(Value::as_str) == Some("Timeout")
        || error
            .get("type")
            .and_then(Value::as_array)
            .and_then(|kind| kind.first())
            .and_then(Value::as_str)
            == Some("PartialParsing")
}

fn describe_recoverable_scan_warning(error: &Value) -> String {
    if error.get("type").and_then(Value::as_str) == Some("Timeout") {
        return error.get("rule_id").and_then(Value::as_str).map_or_else(
            || "OpenGrep rule timed out".to_owned(),
            |rule_id| {
                let rule_id = rule_id
                    .rsplit_once('.')
                    .map_or(rule_id, |(_, identifier)| identifier);
                format!("OpenGrep rule {} timed out", truncate(rule_id, 200))
            },
        );
    }
    let path = error
        .get("path")
        .and_then(Value::as_str)
        .map_or("a target file", |path| {
            path.rsplit('/').next().unwrap_or(path)
        });
    format!("OpenGrep partially parsed {}", truncate(path, 256))
}

fn is_timeout_error(error: &color_eyre::Report) -> bool {
    error.chain().any(|source| {
        source.downcast_ref::<ScanTimeout>().is_some()
            || source
                .downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_timeout)
            || source
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut)
    })
}

fn hash_file(path: &Path, size: u64, deadline: Instant) -> Result<FileIdentity> {
    let mut file = File::open(path)?;
    let mut hasher = Xxh3::new();
    let mut buffer = [0_u8; 8192];
    loop {
        ensure_scan_time_remaining(deadline)?;
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(FileIdentity {
        digest: hasher.digest128(),
        size,
        extension: path.extension().map(OsString::from),
    })
}

fn ensure_scan_time_remaining(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(ScanTimeout("OpenGrep preparation exceeded the distribution deadline").into());
    }
    Ok(())
}

fn rewrite_finding_location(
    finding: &OpenGrepFinding,
    path: &str,
    inspector_base: &Url,
) -> Result<OpenGrepFinding> {
    ensure!(path.len() <= 1024, "finding path exceeds 1024 characters");
    let mut finding = finding.clone();
    path.clone_into(&mut finding.path);
    finding.inspector_url = build_inspector_url(inspector_base, path)?;
    Ok(finding)
}

fn read_bounded(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_OPENGREP_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_OPENGREP_OUTPUT_BYTES,
        "OpenGrep output exceeded {MAX_OPENGREP_OUTPUT_BYTES} bytes"
    );
    Ok(String::from_utf8(bytes)?)
}

fn normalize_finding(
    finding: RawFinding,
    target_directory: &Path,
    inspector_base: &Url,
) -> Result<OpenGrepFinding> {
    let path = relative_target_path(&finding.path, target_directory)?;
    ensure!(
        finding.extra.message.len() <= 1024,
        "finding message exceeds 1024 characters"
    );
    let inspector_url = build_inspector_url(inspector_base, &path)?;
    let rule_id = finding
        .check_id
        .rsplit_once('.')
        .map_or(finding.check_id.as_str(), |(_, identifier)| identifier)
        .to_owned();
    Ok(OpenGrepFinding {
        rule_id,
        path,
        start_line: finding.start.line,
        end_line: finding.end.line,
        message: finding.extra.message,
        severity: finding.extra.severity,
        evidence: finding.extra.metadata.evidence,
        confidence: finding.extra.metadata.confidence,
        execution_context: finding.extra.metadata.execution_context,
        inspector_url,
    })
}

fn relative_target_path(path: &Path, target_directory: &Path) -> Result<String> {
    let relative_path = if path.is_absolute() {
        path.strip_prefix(target_directory)?.to_path_buf()
    } else {
        path.to_path_buf()
    };
    let relative_path = safe_relative_path(
        relative_path
            .to_str()
            .ok_or_else(|| color_eyre::eyre::eyre!("finding path is not UTF-8"))?,
    )?;
    let path = relative_path.to_string_lossy().replace('\\', "/");
    ensure!(path.len() <= 1024, "finding path exceeds 1024 characters");
    Ok(path)
}

fn build_inspector_url(inspector_base: &Url, path: &str) -> Result<String> {
    let inspector_url = format!("{}{}", inspector_base.as_str(), path);
    ensure!(
        inspector_url.len() <= 2048,
        "finding inspector URL exceeds 2048 characters"
    );
    Ok(inspector_url)
}

fn truncate(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        append_findings, hash_file, is_timeout_error, materialize_rules, rules_allow_content_reuse,
        run_opengrep, safe_relative_path, validate_api_origin, PackageTarget, MAX_FINDINGS,
        SCAN_DEADLINE,
    };
    use crate::client::{OpenGrepFinding, OpenGrepRulesResponse};
    use reqwest::Url;
    use std::{
        collections::HashMap,
        ffi::OsStr,
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };
    use tempfile::tempdir;

    fn installed_opengrep_binary() -> Option<PathBuf> {
        static READY: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        let binary = std::env::var_os("OPENGREP_BIN").map(PathBuf::from)?;
        // The portable executable unpacks shared libraries on first use. Finish
        // that cold start before parallel engine tests use the same cache.
        READY.get_or_init(|| {
            let output = std::process::Command::new(&binary)
                .arg("--version")
                .env("HOME", "/tmp")
                .env("XDG_CACHE_HOME", "/tmp")
                .env("OPENGREP_ENABLE_VERSION_CHECK", "0")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        });
        Some(binary)
    }

    fn reuse_test_client(
        binary: PathBuf,
        mode: crate::reuse_cache::CacheMode,
    ) -> super::OpenGrepClient {
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("rule.yml"),
            r"
rules:
  - id: python-test-exec
    message: Dynamic execution.
    languages: [python]
    severity: ERROR
    metadata:
      evidence: composition
      confidence: high
      execution_context: import_time
    pattern: exec(...)
",
        )
        .unwrap();
        super::OpenGrepClient {
            api_client: reqwest::blocking::Client::new(),
            download_client: reqwest::blocking::Client::new(),
            base_url: "https://dragonfly-staging.vipyrsec.com".into(),
            binary,
            rules_directory: directory,
            content_reuse_safe: true,
            rules_hash: "snapshot".into(),
            reuse_cache: crate::reuse_cache::ReuseCache::new(mode, 100, 1024 * 1024),
        }
    }

    #[test]
    fn sampled_mismatch_rejects_previously_selected_cache_hits() {
        use crate::reuse_cache::{CacheMode, CacheStats};
        let Some(binary) = installed_opengrep_binary() else {
            return;
        };
        for mode in [CacheMode::Observe, CacheMode::Reuse] {
            let client = reuse_test_client(binary.clone(), mode);
            let source = tempdir().unwrap();
            std::fs::write(source.path().join("one.py"), "exec('one')\n").unwrap();
            std::fs::write(source.path().join("two.py"), "exec('two')\n").unwrap();
            let mut target = PackageTarget::new().unwrap();
            let plan = target
                .plan_distribution(source.path(), Instant::now() + SCAN_DEADLINE)
                .unwrap();
            target
                .commit_distribution(plan, Url::parse("https://inspector.example/").unwrap())
                .unwrap();
            let mut stats = CacheStats::new("opengrep", mode);
            for (identity, target_id) in &target.identities {
                let path = target.target_path(*target_id, identity.extension.as_deref());
                let key = format!(
                    "{:032x}:{}:{:?}",
                    identity.digest, identity.size, identity.extension
                );
                client.reuse_cache.insert(
                    key,
                    &path,
                    &Vec::<crate::client::OpenGrepFinding>::new(),
                    &mut stats,
                );
            }
            if mode == CacheMode::Reuse {
                for _ in 0..98 {
                    assert!(client.reuse_cache.should_reuse());
                }
            }
            let job = crate::client::Job {
                hash: "snapshot".into(),
                name: "test".into(),
                version: "1".into(),
                distributions: Vec::new(),
                attempt: 1,
                assignment_id: "lease".into(),
            };
            let outcome =
                client.scan_prepared_package(&mut target, 1, Vec::new(), &job, &mut stats);
            if mode == CacheMode::Reuse {
                assert!(outcome.is_err());
                assert_eq!(stats.reused_files, 1);
                assert_eq!(stats.mismatched_files, 1);
            } else {
                assert_eq!(outcome.unwrap().findings.len(), 2);
                assert_eq!(stats.reused_files, 0);
                assert_eq!(stats.mismatched_files, 2);
            }
            assert!(client.reuse_cache.is_disabled());
        }
    }

    #[test]
    fn production_report_serializes_flat_success_and_failure_with_metrics() {
        use crate::client::{
            OpenGrepScanResult, SubmitOpenGrepResultsError, SubmitOpenGrepResultsSuccess,
        };
        use crate::reuse_cache::{CacheMode, CacheStats};
        for success in [true, false] {
            let result = if success {
                OpenGrepScanResult::Success(SubmitOpenGrepResultsSuccess {
                    name: "test".into(),
                    version: "1".into(),
                    attempt: 1,
                    assignment_id: "lease".into(),
                    commit: "rules".into(),
                    duration_ms: 123,
                    findings: Vec::new(),
                    partial_reason: None,
                })
            } else {
                OpenGrepScanResult::Error(SubmitOpenGrepResultsError {
                    name: "test".into(),
                    version: "1".into(),
                    attempt: 1,
                    assignment_id: "lease".into(),
                    duration_ms: 123,
                    reason: "failure".into(),
                })
            };
            let mut metrics = CacheStats::new("opengrep", CacheMode::Reuse);
            metrics.reused_files = 2;
            let report = super::ReportedOpenGrepResult {
                result,
                scan_reuse: metrics,
            };
            let (base_url, request) = crate::client::serve_once("");
            let http = reqwest::blocking::Client::new();
            crate::client::send_opengrep_result(&http, &base_url, &report).unwrap();
            let request = request.recv().unwrap();
            assert!(request.starts_with("PUT /opengrep/package HTTP/1.1\r\n"));
            let body: serde_json::Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(body["assignment_id"], "lease");
            assert_eq!(body["name"], "test");
            assert_eq!(body["scan_reuse"]["mode"], "reuse");
            assert_eq!(body["scan_reuse"]["reused_files"], 2);
            assert_eq!(body.get("findings").is_some(), success);
            assert_eq!(body.get("reason").is_some(), !success);
            assert!(body.get("result").is_none());
        }
    }

    #[test]
    fn installed_opengrep_reuses_across_packages_and_rewrites_locations() {
        use crate::reuse_cache::{CacheMode, CacheStats};
        let Some(binary) = installed_opengrep_binary() else {
            return;
        };
        for mode in [CacheMode::Observe, CacheMode::Reuse] {
            let client = reuse_test_client(binary.clone(), mode);
            let job = crate::client::Job {
                hash: "snapshot".into(),
                name: "test".into(),
                version: "1".into(),
                distributions: Vec::new(),
                attempt: 1,
                assignment_id: "lease".into(),
            };
            for version in 1..=2 {
                let source = tempdir().unwrap();
                std::fs::write(source.path().join("danger.py"), "exec('print(1)')\n").unwrap();
                std::fs::write(source.path().join("clean.py"), "print(1)\n").unwrap();
                // A target without a supported language must not become a cached clean result.
                std::fs::write(source.path().join("ignored.unknown"), "text\n").unwrap();
                let mut target = PackageTarget::new().unwrap();
                let plan = target
                    .plan_distribution(source.path(), Instant::now() + SCAN_DEADLINE)
                    .unwrap();
                target
                    .commit_distribution(
                        plan,
                        Url::parse(&format!("https://inspector.example/v{version}/")).unwrap(),
                    )
                    .unwrap();
                let mut stats = CacheStats::new("test", mode);
                let outcome = client
                    .scan_prepared_package(&mut target, 1, Vec::new(), &job, &mut stats)
                    .unwrap();
                assert!(outcome.partial_reason.is_none());
                assert_eq!(outcome.findings.len(), 1);
                assert_eq!(outcome.findings[0].path, "danger.py");
                assert!(outcome.findings[0]
                    .inspector_url
                    .contains(&format!("/v{version}/")));
                assert_eq!(stats.inserted_files, if version == 1 { 2 } else { 0 });
                assert_eq!(
                    stats.reused_files,
                    if version == 2 && mode == CacheMode::Reuse {
                        2
                    } else {
                        0
                    }
                );
                assert_eq!(
                    stats.validated_files,
                    if version == 2 && mode == CacheMode::Observe {
                        2
                    } else {
                        0
                    }
                );
                assert_eq!(stats.mismatched_files, 0);
            }
        }
    }

    #[test]
    fn installed_opengrep_does_not_cache_partial_package_results() {
        use crate::reuse_cache::{CacheMode, CacheStats};
        let Some(binary) = installed_opengrep_binary() else {
            return;
        };
        let client = reuse_test_client(binary, CacheMode::Reuse);
        let source = tempdir().unwrap();
        std::fs::write(source.path().join("clean.py"), "print(1)\n").unwrap();
        let mut target = PackageTarget::new().unwrap();
        let plan = target
            .plan_distribution(source.path(), Instant::now() + SCAN_DEADLINE)
            .unwrap();
        target
            .commit_distribution(plan, Url::parse("https://inspector.example/").unwrap())
            .unwrap();
        let job = crate::client::Job {
            hash: "snapshot".into(),
            name: "test".into(),
            version: "1".into(),
            distributions: Vec::new(),
            attempt: 1,
            assignment_id: "lease".into(),
        };
        let mut stats = CacheStats::new("test", CacheMode::Reuse);
        let outcome = client
            .scan_prepared_package(
                &mut target,
                1,
                vec!["incomplete download".into()],
                &job,
                &mut stats,
            )
            .unwrap();
        assert!(outcome.partial_reason.is_some());
        assert_eq!(stats.inserted_files, 0);
    }

    #[test]
    fn shadow_origin_is_restricted_to_supported_apis() {
        validate_api_origin("https://dragonfly-staging.vipyrsec.com").unwrap();
        validate_api_origin("https://dragonfly-staging.vipyrsec.com/").unwrap();

        validate_api_origin("https://dragonfly.vipyrsec.com").unwrap();
        validate_api_origin("https://dragonfly.vipyrsec.com/").unwrap();

        for rejected in [
            "https://dragonfly.vipyrsec.com.evil.example",
            "https://user@dragonfly.vipyrsec.com",
            "https://dragonfly.vipyrsec.com:444",
            "https://dragonfly.vipyrsec.com/#fragment",
            "http://dragonfly-staging.vipyrsec.com",
            "https://dragonfly-staging.vipyrsec.com/other",
            "https://dragonfly-staging.vipyrsec.com?redirect=production",
        ] {
            assert!(validate_api_origin(rejected).is_err());
        }
    }

    #[test]
    fn rule_paths_cannot_escape_the_temporary_directory() {
        for rejected in [
            "",
            "/absolute.yml",
            "../outside.yml",
            "python/../outside.yml",
        ] {
            assert!(safe_relative_path(rejected).is_err());
        }
        assert_eq!(
            safe_relative_path("python/payload.yml").unwrap(),
            Path::new("python/payload.yml")
        );
    }

    #[test]
    fn rules_are_materialized_with_their_relative_paths() {
        let response = OpenGrepRulesResponse {
            hash: "commit".to_owned(),
            rules: HashMap::from([("python/payload.yml".to_owned(), "rules: []".to_owned())]),
        };

        let directory = materialize_rules(&response).unwrap();

        assert_eq!(
            std::fs::read_to_string(directory.path().join("python/payload.yml")).unwrap(),
            "rules: []"
        );
    }

    #[test]
    fn installed_opengrep_structurally_detects_path_scoped_rules() {
        let Some(binary) = installed_opengrep_binary() else {
            return;
        };
        let rules = tempdir().unwrap();
        let rule_path = rules.path().join("rule.yml");
        std::fs::write(
            &rule_path,
            "rules:\n  - id: content-only\n    message: test\n    languages: [python]\n    severity: ERROR\n    pattern: exec(...)\n",
        )
        .unwrap();
        assert!(rules_allow_content_reuse(&binary, rules.path()).unwrap());

        std::fs::write(
            rule_path,
            "rules:\n  - id: path-scoped\n    message: test\n    languages: [python]\n    severity: ERROR\n    'paths' : {include: [src/**]}\n    pattern: exec(...)\n",
        )
        .unwrap();
        assert!(!rules_allow_content_reuse(&binary, rules.path()).unwrap());
        std::fs::write(rules.path().join("rule.yml"),
            "rules:\n  - id: interfile\n    message: test\n    languages: [python]\n    severity: ERROR\n    options: {interfile: true}\n    pattern: exec(...)\n").unwrap();
        assert!(!rules_allow_content_reuse(&binary, rules.path()).unwrap());
    }

    #[test]
    fn installed_opengrep_matches_the_expected_json_contract() {
        let Some(binary) = installed_opengrep_binary() else {
            return;
        };
        let rules = tempdir().unwrap();
        let target = tempdir().unwrap();
        std::fs::write(
            rules.path().join("rule.yml"),
            r"
rules:
  - id: python-test-exec
    message: Dynamic execution.
    languages: [python]
    severity: ERROR
    metadata:
      evidence: composition
      confidence: high
      execution_context: import_time
    pattern: exec(...)
",
        )
        .unwrap();
        std::fs::write(target.path().join("sample.py"), "exec('safe fixture')\n").unwrap();
        let inspector = Url::parse("https://inspector.example/packages/sample/").unwrap();

        let run = run_opengrep(
            &binary,
            rules.path(),
            target.path(),
            &inspector,
            SCAN_DEADLINE,
        )
        .unwrap();

        assert_eq!(run.findings.len(), 1);
        assert_eq!(run.findings[0].rule_id, "python-test-exec");
        assert_eq!(run.findings[0].path, "sample.py");
        assert_eq!(run.findings[0].execution_context, "import_time");
        assert!(run.warnings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn partial_parse_warnings_preserve_valid_findings() {
        use std::os::unix::fs::PermissionsExt;

        let rules = tempdir().unwrap();
        let target = tempdir().unwrap();
        let binary = target.path().join("partial-opengrep");
        std::fs::write(
            &binary,
            r#"#!/bin/sh
for argument in "$@"; do
  if [ "$argument" = "--strict" ]; then
    exit 2
  fi
done
printf '%s' '{
  "results": [{
    "check_id": "python-test-exec",
    "path": "sample.py",
    "start": {"line": 1},
    "end": {"line": 1},
    "extra": {
      "message": "Dynamic execution.",
      "severity": "ERROR",
      "metadata": {
        "evidence": "composition",
        "confidence": "high",
        "execution_context": "import_time"
      }
    }
  }],
  "errors": [{
    "code": 3,
    "level": "warn",
    "message": "Syntax error",
    "path": "other.py",
    "type": ["PartialParsing", []]
  }],
  "skipped_rules": []
}'
"#,
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&binary, permissions).unwrap();
        let inspector = Url::parse("https://inspector.example/packages/sample/").unwrap();

        let run = run_opengrep(
            &binary,
            rules.path(),
            target.path(),
            &inspector,
            SCAN_DEADLINE,
        )
        .unwrap();

        assert_eq!(run.findings.len(), 1);
        assert_eq!(run.findings[0].rule_id, "python-test-exec");
        assert_eq!(run.warnings.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn rule_timeouts_preserve_valid_findings() {
        use std::os::unix::fs::PermissionsExt;

        let rules = tempdir().unwrap();
        let target = tempdir().unwrap();
        let binary = target.path().join("errored-opengrep");
        std::fs::write(
            &binary,
            r#"#!/bin/sh
printf '%s' '{
  "results": [{
    "check_id": "python-test-exec",
    "path": "sample.py",
    "start": {"line": 1},
    "end": {"line": 1},
    "extra": {
      "message": "Dynamic execution.",
      "severity": "ERROR",
      "metadata": {
        "evidence": "composition",
        "confidence": "high",
        "execution_context": "import_time"
      }
    }
  }],
  "errors": [{
    "code": 2,
    "level": "warn",
    "message": "Rule timed out",
    "type": "Timeout"
  }],
  "skipped_rules": []
}'
"#,
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&binary, permissions).unwrap();
        let inspector = Url::parse("https://inspector.example/packages/sample/").unwrap();

        let run = run_opengrep(
            &binary,
            rules.path(),
            target.path(),
            &inspector,
            SCAN_DEADLINE,
        )
        .unwrap();

        assert_eq!(run.findings.len(), 1);
        assert_eq!(run.warnings.len(), 1);
        assert_eq!(run.warnings[0], "OpenGrep rule timed out");
    }

    #[test]
    fn package_target_deduplicates_and_maps_distribution_aliases() {
        let first_distribution = tempdir().unwrap();
        let nested = first_distribution.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(
            first_distribution.path().join("first.py"),
            "print('same')\n",
        )
        .unwrap();
        std::fs::write(nested.join("duplicate.py"), "print('same')\n").unwrap();
        std::fs::write(
            first_distribution.path().join("different.txt"),
            "print('same')\n",
        )
        .unwrap();
        let first_inspector = Url::parse("https://inspector.example/first/").unwrap();
        let mut package_target = PackageTarget::new().unwrap();
        let first_plan = package_target
            .plan_distribution(first_distribution.path(), Instant::now() + SCAN_DEADLINE)
            .unwrap();
        package_target
            .commit_distribution(first_plan, first_inspector)
            .unwrap();

        let second_distribution = tempdir().unwrap();
        std::fs::write(
            second_distribution.path().join("other.py"),
            "print('same')\n",
        )
        .unwrap();
        std::fs::write(
            second_distribution.path().join("other.js"),
            "print('same')\n",
        )
        .unwrap();
        let second_inspector = Url::parse("https://inspector.example/second/").unwrap();
        let second_plan = package_target
            .plan_distribution(second_distribution.path(), Instant::now() + SCAN_DEADLINE)
            .unwrap();
        package_target
            .commit_distribution(second_plan, second_inspector)
            .unwrap();

        assert_eq!(package_target.target_count(), 3);
        assert_eq!(package_target.deduplicated_files, 2);
        assert_eq!(std::fs::read_dir(package_target.path()).unwrap().count(), 3);

        let canonical_finding = OpenGrepFinding {
            rule_id: "python-test-exec".to_owned(),
            path: "0000000000000001.py".to_owned(),
            start_line: 1,
            end_line: 1,
            message: "Dynamic execution.".to_owned(),
            severity: "ERROR".to_owned(),
            evidence: "composition".to_owned(),
            confidence: "high".to_owned(),
            execution_context: "import_time".to_owned(),
            inspector_url: "https://opengrep-target.invalid/0000000000000001.py".to_owned(),
        };
        let expanded = package_target
            .expand_findings(vec![canonical_finding])
            .unwrap();
        assert_eq!(expanded.len(), 3);
        assert!(expanded.iter().any(|finding| {
            finding.path == "nested/duplicate.py"
                && finding.inspector_url == "https://inspector.example/first/nested/duplicate.py"
        }));
        assert!(expanded.iter().any(|finding| {
            finding.path == "first.py"
                && finding.inspector_url == "https://inspector.example/first/first.py"
        }));
        assert!(expanded.iter().any(|finding| {
            finding.path == "other.py"
                && finding.inspector_url == "https://inspector.example/second/other.py"
        }));

        let mut bounded = vec![expanded[0].clone(); MAX_FINDINGS];
        assert!(append_findings(&mut bounded, expanded).is_err());
        assert_eq!(bounded.len(), MAX_FINDINGS);
    }

    #[cfg(unix)]
    #[test]
    fn prepared_package_uses_one_opengrep_invocation() {
        use std::os::unix::fs::PermissionsExt;

        let first_distribution = tempdir().unwrap();
        let second_distribution = tempdir().unwrap();
        std::fs::write(first_distribution.path().join("first.py"), "exec('same')\n").unwrap();
        std::fs::write(
            second_distribution.path().join("second.py"),
            "exec('same')\n",
        )
        .unwrap();
        let mut package_target = PackageTarget::new().unwrap();
        for (directory, inspector) in [
            (
                &first_distribution,
                Url::parse("https://inspector.example/first/").unwrap(),
            ),
            (
                &second_distribution,
                Url::parse("https://inspector.example/second/").unwrap(),
            ),
        ] {
            let plan = package_target
                .plan_distribution(directory.path(), Instant::now() + SCAN_DEADLINE)
                .unwrap();
            package_target.commit_distribution(plan, inspector).unwrap();
        }

        let fixture = tempdir().unwrap();
        let marker = fixture.path().join("invocations");
        let binary = fixture.path().join("fake-opengrep");
        std::fs::write(
            &binary,
            format!(
                r#"#!/bin/sh
printf 'x\n' >> '{}'
for argument in "$@"; do target=$argument; done
for file in "$target"/*.py; do path=${{file##*/}}; break; done
printf '{{"results":[{{"check_id":"python-test-exec","path":"%s","start":{{"line":1}},"end":{{"line":1}},"extra":{{"message":"Dynamic execution.","severity":"ERROR","metadata":{{"evidence":"composition","confidence":"high","execution_context":"import_time"}}}}}}],"errors":[],"skipped_rules":[]}}' "$path"
"#,
                marker.display()
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&binary, permissions).unwrap();
        let rules = tempdir().unwrap();
        let placeholder = Url::parse("https://opengrep-target.invalid/").unwrap();

        let run = run_opengrep(
            &binary,
            rules.path(),
            package_target.path(),
            &placeholder,
            SCAN_DEADLINE,
        )
        .unwrap();
        let expanded = package_target.expand_findings(run.findings).unwrap();

        assert_eq!(std::fs::read_to_string(marker).unwrap(), "x\n");
        assert_eq!(package_target.target_count(), 1);
        assert_eq!(expanded.len(), 2);
        assert!(expanded.iter().any(|finding| finding.path == "first.py"));
        assert!(expanded.iter().any(|finding| finding.path == "second.py"));
    }

    #[test]
    fn file_identity_uses_xxh3_128_and_size() {
        let target = tempdir().unwrap();
        let path = target.path().join("sample.py");
        let contents = b"print('sample')\n";
        std::fs::write(&path, contents).unwrap();

        let size = u64::try_from(contents.len()).unwrap();
        let identity = hash_file(&path, size, Instant::now() + SCAN_DEADLINE).unwrap();

        assert_eq!(identity.digest, xxhash_rust::xxh3::xxh3_128(contents));
        assert_eq!(identity.size, size);
        assert_eq!(identity.extension.as_deref(), Some(OsStr::new("py")));
    }

    #[test]
    fn package_target_preparation_is_transactional_on_timeout() {
        let target = tempdir().unwrap();
        std::fs::write(target.path().join("first.py"), "print('same')\n").unwrap();
        let package_target = PackageTarget::new().unwrap();

        let error = package_target
            .plan_distribution(target.path(), Instant::now())
            .unwrap_err();

        assert!(is_timeout_error(&error));
        assert!(package_target.is_empty());
        assert_eq!(std::fs::read_dir(package_target.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn opengrep_is_killed_while_its_output_exceeds_the_limit() {
        use std::os::unix::fs::PermissionsExt;

        let rules = tempdir().unwrap();
        let target = tempdir().unwrap();
        let binary = target.path().join("oversized-opengrep");
        std::fs::write(
            &binary,
            "#!/bin/sh\ndd if=/dev/zero bs=1048576 count=5 2>/dev/null\nsleep 5\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&binary, permissions).unwrap();
        let inspector = Url::parse("https://inspector.example/packages/sample/").unwrap();

        let error = run_opengrep(
            &binary,
            rules.path(),
            target.path(),
            &inspector,
            Duration::from_secs(2),
        )
        .unwrap_err();

        assert!(error.to_string().contains("output exceeded"));
    }
}
