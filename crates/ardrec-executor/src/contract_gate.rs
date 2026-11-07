//! ARDREC P8 R2-C.24 / pure, deterministic, deny-only contract grammar.
//!
//! No executable resolution, file I/O, network, credentials, process construction,
//! dispatch, or operational authorization. Every review is blocked by design.
//! A well-formed synthetic proposal is NOT an approved execution profile.
//! R2-C.25: shadow-integrated API; all decisions remain blocked.

use std::collections::BTreeSet;

/// ARDREC deny-only contract field or declaration: BASELINE_COMMIT.
pub const BASELINE_COMMIT: &str = "01755acf248b75daa55b2afe7b1e60a462e984f6";
/// ARDREC deny-only contract field or declaration: P7_SHA256.
pub const P7_SHA256: &str = "5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e";
/// ARDREC deny-only contract field or declaration: P8_SHA256.
pub const P8_SHA256: &str = "fe0fae200ac031622d27020b77d38bd18a22e3ffaa0dd0f57ec4e9f01f284ce3";
/// ARDREC deny-only contract field or declaration: PROFILE_COUNT.
pub const PROFILE_COUNT: usize = 29;
/// ARDREC deny-only contract field or declaration: BINDING_FIELDS.
pub const BINDING_FIELDS: usize = 12;
/// ARDREC deny-only contract field or declaration: MAX_ATTEMPTS.
pub const MAX_ATTEMPTS: u32 = 1;
/// ARDREC deny-only contract field or declaration: MAX_DRAFT_TIMEOUT_MS.
pub const MAX_DRAFT_TIMEOUT_MS: u32 = 60_000;
/// ARDREC deny-only contract field or declaration: MAX_DRAFT_OUTPUT_BYTES.
pub const MAX_DRAFT_OUTPUT_BYTES: u32 = 1_048_576;

/// Intentionally only an inventory, never a dispatch registry.
pub const PROFILE_IDS: [&str; 29] = [
    "SSH-T01-BASE",
    "SSH-T02-BASE",
    "SSH-T03-BASE",
    "SSH-T04-BASE",
    "SSH-T05-BASE",
    "SSH-T06-BASE",
    "SSH-T07-BASE",
    "SSH-T08-BASE",
    "FTP-T01-BASE",
    "FTP-T02-CONTROL",
    "FTP-T02-DATA",
    "FTP-T03-BASE",
    "FTP-T04-BASE",
    "FTP-T05-BASE",
    "FTP-T06-BASE",
    "FTP-T07-BASE",
    "FTP-T08-READ",
    "FTP-T08-WRITE",
    "SMB-T01-BASE",
    "SMB-T02-BASE",
    "SMB-T03-SIGNING",
    "SMB-T03-ENCRYPTION",
    "SMB-T04-BASE",
    "SMB-T05-BASE",
    "SMB-T06-BASE",
    "SMB-T07-BASE",
    "SMB-T08-BASE",
    "SMB-T09-READ",
    "SMB-T09-WRITE",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// ARDREC deny-only contract field or declaration: Protocol.
pub enum Protocol {
    /// SSH protocol family.
    Ssh,
    /// FTP protocol family.
    Ftp,
    /// SMB protocol family.
    Smb,
}

impl Protocol {
    fn prefix(self) -> &'static str {
        match self {
            Self::Ssh => "SSH-",
            Self::Ftp => "FTP-",
            Self::Smb => "SMB-",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// ARDREC deny-only contract field or declaration: Variant.
pub enum Variant {
    /// Control branch of a split specification.
    Control,
    /// Data branch of a split specification.
    Data,
    /// Read branch of a split specification.
    Read,
    /// Write branch of a split specification.
    Write,
    /// Signing branch of a split specification.
    Signing,
    /// Encryption branch of a split specification.
    Encryption,
}

impl Variant {
    /// ARDREC deny-only contract field or declaration: label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Control => "CONTROL",
            Self::Data => "DATA",
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Signing => "SIGNING",
            Self::Encryption => "ENCRYPTION",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// ARDREC deny-only contract field or declaration: Cleanup.
pub enum Cleanup {
    /// No mutation is permitted.
    NoMutation,
    /// Requires verified marker removal and cleanup.
    VerifyThenRemoveMarker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// ARDREC deny-only contract field or declaration: Observation.
pub enum Observation {
    /// Synthetic precondition affirmed.
    True,
    /// Synthetic precondition rejected.
    False,
    /// Synthetic precondition undetermined; always blocks.
    NotDetermined,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// ARDREC deny-only contract field or declaration: ArgToken.
pub enum ArgToken {
    /// A bounded literal argument token; never a shell command.
    Literal(String),
    /// Reference to a declared material parameter slot.
    MaterialSlot(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// ARDREC deny-only contract field or declaration: Auxiliary.
pub struct Auxiliary {
    /// Absolute binary path; syntactic review only.
    pub path: String,
    /// SHA-256 hex digest declared by the proposal, not independently authenticated.
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// ARDREC deny-only contract field or declaration: Budget.
pub struct Budget {
    /// ARDREC deny-only contract field or declaration: max_attempts.
    pub max_attempts: u32,
    /// ARDREC deny-only contract field or declaration: timeout_ms.
    pub timeout_ms: u32,
    /// ARDREC deny-only contract field or declaration: max_stdout_bytes.
    pub max_stdout_bytes: u32,
    /// ARDREC deny-only contract field or declaration: max_stderr_bytes.
    pub max_stderr_bytes: u32,
}

/// In-memory proposal; has no execution method and cannot represent approval.
#[derive(Clone, Debug, Default)]
/// ARDREC deny-only contract field or declaration: Draft.
pub struct Draft {
    /// ARDREC deny-only contract field or declaration: executable_absolute_path.
    pub executable_absolute_path: Option<String>,
    /// ARDREC deny-only contract field or declaration: executable_sha256.
    pub executable_sha256: Option<String>,
    /// ARDREC deny-only contract field or declaration: executable_version.
    pub executable_version: Option<String>,
    /// ARDREC deny-only contract field or declaration: argv_typed_vector.
    pub argv_typed_vector: Option<Vec<ArgToken>>,
    /// ARDREC deny-only contract field or declaration: working_directory.
    pub working_directory: Option<String>,
    /// ARDREC deny-only contract field or declaration: environment_allowlist.
    pub environment_allowlist: Option<Vec<(String, String)>>,
    /// ARDREC deny-only contract field or declaration: auxiliary_executables.
    pub auxiliary_executables: Option<Vec<Auxiliary>>,
    /// ARDREC deny-only contract field or declaration: case_authorization_ref.
    pub case_authorization_ref: Option<String>,
    /// ARDREC deny-only contract field or declaration: approved_target_ref.
    pub approved_target_ref: Option<String>,
    /// ARDREC deny-only contract field or declaration: fixed_resource_budget.
    pub fixed_resource_budget: Option<Budget>,
    /// ARDREC deny-only contract field or declaration: capture_policy_ref.
    pub capture_policy_ref: Option<String>,
    /// ARDREC deny-only contract field or declaration: cleanup_receipt_ref.
    pub cleanup_receipt_ref: Option<String>,
}

/// An unbound P8 definition, not a verified capability or runtime profile.
#[derive(Clone, Debug)]
/// ARDREC deny-only contract field or declaration: Definition.
pub struct Definition<'a> {
    /// ARDREC deny-only contract field or declaration: profile_id.
    pub profile_id: &'a str,
    /// ARDREC deny-only contract field or declaration: family_id.
    pub family_id: &'a str,
    /// ARDREC deny-only contract field or declaration: protocol.
    pub protocol: Protocol,
    /// ARDREC deny-only contract field or declaration: variant.
    pub variant: Option<Variant>,
    /// ARDREC deny-only contract field or declaration: cleanup.
    pub cleanup: Cleanup,
    /// ARDREC deny-only contract field or declaration: required_material_slots.
    pub required_material_slots: &'a [&'a str],
    /// ARDREC deny-only contract field or declaration: required_preconditions.
    pub required_preconditions: &'a [&'a str],
    /// ARDREC deny-only contract field or declaration: required_supports.
    pub required_supports: &'a [&'a str],
    /// ARDREC deny-only contract field or declaration: status.
    pub status: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// ARDREC deny-only contract field or declaration: Finding.
pub enum Finding {
    /// Syntactic denial finding; never grants authorization.
    InvalidProfile,
    /// Syntactic denial finding; never grants authorization.
    InvalidProfileStatus,
    /// Syntactic denial finding; never grants authorization.
    InvalidDefinition,
    /// Syntactic denial finding; never grants authorization.
    MissingField(&'static str),
    /// Syntactic denial finding; never grants authorization.
    InvalidExecutable,
    /// Syntactic denial finding; never grants authorization.
    InvalidSha256,
    /// Syntactic denial finding; never grants authorization.
    InvalidVersion,
    /// Syntactic denial finding; never grants authorization.
    InvalidArguments,
    /// Syntactic denial finding; never grants authorization.
    InvalidEnvironment,
    /// Syntactic denial finding; never grants authorization.
    InvalidAuxiliary,
    /// Syntactic denial finding; never grants authorization.
    InvalidReference,
    /// Syntactic denial finding; never grants authorization.
    InvalidBudget,
    /// Syntactic denial finding; never grants authorization.
    UnmetPreconditions,
    /// All structural checks passed, but operational authorization is unavailable.
    AuthorizationUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// ARDREC deny-only contract field or declaration: Decision.
pub enum Decision {
    /// No operational dispatch or authorization is possible.
    BlockedUnboundNoExecution,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// ARDREC deny-only contract field or declaration: Review.
pub struct Review {
    /// ARDREC deny-only contract field or declaration: decision.
    pub decision: Decision,
    /// ARDREC deny-only contract field or declaration: dispatch_allowed.
    pub dispatch_allowed: bool,
    /// ARDREC deny-only contract field or declaration: authorized.
    pub authorized: bool,
    /// ARDREC deny-only contract field or declaration: findings.
    pub findings: Vec<Finding>,
}

fn safe_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn safe_absolute(value: &str) -> bool {
    value.len() <= 255
        && value.starts_with('/')
        && !value.bytes().any(|c| c.is_ascii_control() || c == b'\\')
        && value
            .split('/')
            .skip(1)
            .all(|s| !s.is_empty() && s != "." && s != "..")
}

fn forbidden_binary(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "ksh"
            | "fish"
            | "cmd.exe"
            | "powershell.exe"
            | "env"
            | "busybox"
    )
}

fn safe_executable(value: &str) -> bool {
    safe_absolute(value)
        && (value.starts_with("/usr/bin/") || value.starts_with("/usr/sbin/"))
        && value
            .rsplit('/')
            .next()
            .is_some_and(|n| !forbidden_binary(n))
}

fn safe_reference(value: &str) -> bool {
    let Some(body) = value.strip_prefix("ref:") else {
        return false;
    };
    (3..=128).contains(&body.len())
        && !body.contains("..")
        && body
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && body
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:/-".contains(&c))
}

fn safe_version(value: &str) -> bool {
    (1..=160).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b" ._:+~()/-".contains(&c))
}

fn safe_literal(value: &str) -> bool {
    (1..=256).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:/@=,+%-".contains(&c))
        && !forbidden_binary(value)
}

fn unique_nonempty(values: &[&str]) -> bool {
    !values.is_empty()
        && values.iter().all(|s| !s.is_empty())
        && values.iter().copied().collect::<BTreeSet<_>>().len() == values.len()
}

fn valid_definition(def: &Definition<'_>) -> bool {
    if def.status != "BLOCKED_UNBOUND_NO_EXECUTION"
        || !PROFILE_IDS.contains(&def.profile_id)
        || !def.profile_id.starts_with(def.protocol.prefix())
        || !def.family_id.starts_with(def.protocol.prefix())
        || !def.profile_id.starts_with(&format!("{}-", def.family_id))
        || !unique_nonempty(def.required_material_slots)
        || !unique_nonempty(def.required_preconditions)
        || !unique_nonempty(def.required_supports)
    {
        return false;
    }

    let suffix = def.variant.map_or("BASE", Variant::label);
    if def.profile_id != format!("{}-{suffix}", def.family_id) {
        return false;
    }

    match def.profile_id {
        "FTP-T02-CONTROL" | "FTP-T02-DATA" => {
            if !matches!(def.variant, Some(Variant::Control | Variant::Data)) {
                return false;
            }
        }
        "FTP-T08-READ" | "FTP-T08-WRITE" | "SMB-T09-READ" | "SMB-T09-WRITE" => {
            if !matches!(def.variant, Some(Variant::Read | Variant::Write)) {
                return false;
            }
        }
        "SMB-T03-SIGNING" | "SMB-T03-ENCRYPTION" => {
            if !matches!(def.variant, Some(Variant::Signing | Variant::Encryption)) {
                return false;
            }
        }
        _ => {
            if def.variant.is_some() {
                return false;
            }
        }
    }

    if (def.cleanup == Cleanup::VerifyThenRemoveMarker || def.variant == Some(Variant::Write))
        && (def.cleanup != Cleanup::VerifyThenRemoveMarker
            || !["MARKER_CREATED", "MARKER_VERIFIED", "CLEANUP_CONFIRMED"]
                .iter()
                .all(|s| def.required_supports.contains(s))
            || !def.required_preconditions.contains(&"CLEANUP_VERIFIABLE"))
    {
        return false;
    }

    if def.required_supports.contains(&"PRIVILEGE_SCOPE")
        && !def
            .required_preconditions
            .contains(&"PRIVILEGE_SCOPE_EXPLICITLY_APPROVED")
    {
        return false;
    }

    true
}

/// Evaluate grammar in memory; even success always yields a DENIAL, never an argv.
/// `observed` is synthetic and cannot establish authoritative case preconditions.
pub fn review(def: &Definition<'_>, draft: &Draft, observed: &[(&str, Observation)]) -> Review {
    let mut findings = Vec::new();
    if def.status != "BLOCKED_UNBOUND_NO_EXECUTION" {
        findings.push(Finding::InvalidProfileStatus);
    }
    if !PROFILE_IDS.contains(&def.profile_id) {
        findings.push(Finding::InvalidProfile);
    }
    if !valid_definition(def) {
        findings.push(Finding::InvalidDefinition);
    }

    macro_rules! field {
        ($name:ident) => {
            if draft.$name.is_none() {
                findings.push(Finding::MissingField(stringify!($name)));
            }
        };
    }
    field!(executable_absolute_path);
    field!(executable_sha256);
    field!(executable_version);
    field!(argv_typed_vector);
    field!(working_directory);
    field!(environment_allowlist);
    field!(auxiliary_executables);
    field!(case_authorization_ref);
    field!(approved_target_ref);
    field!(fixed_resource_budget);
    field!(capture_policy_ref);
    field!(cleanup_receipt_ref);

    if let Some(path) = &draft.executable_absolute_path
        && !safe_executable(path)
    {
        findings.push(Finding::InvalidExecutable);
    }
    if let Some(hash) = &draft.executable_sha256
        && !safe_hash(hash)
    {
        findings.push(Finding::InvalidSha256);
    }
    if let Some(version) = &draft.executable_version
        && !safe_version(version)
    {
        findings.push(Finding::InvalidVersion);
    }
    if let Some(workdir) = &draft.working_directory
        && (!safe_absolute(workdir) || workdir.starts_with("/usr/"))
    {
        findings.push(Finding::InvalidExecutable);
    }
    if let Some(argv) = &draft.argv_typed_vector {
        let mut slots = BTreeSet::new();
        if argv.is_empty()
            || argv.len() > 24
            || argv.iter().any(|t| match t {
                ArgToken::Literal(s) => !safe_literal(s),
                ArgToken::MaterialSlot(s) => {
                    !def.required_material_slots.contains(&s.as_str()) || !slots.insert(s.as_str())
                }
            })
        {
            findings.push(Finding::InvalidArguments);
        }
    }
    if let Some(env) = &draft.environment_allowlist {
        let mut keys = BTreeSet::new();
        if env.len() > 3
            || env.iter().any(|(k, v)| {
                !keys.insert(k.as_str())
                    || !matches!(
                        (k.as_str(), v.as_str()),
                        ("LANG", "C") | ("LC_ALL", "C") | ("TZ", "UTC")
                    )
            })
        {
            findings.push(Finding::InvalidEnvironment);
        }
    }
    if let Some(aux) = &draft.auxiliary_executables {
        let mut seen = BTreeSet::new();
        if aux.len() > 8
            || aux.iter().any(|a| {
                !safe_executable(&a.path) || !safe_hash(&a.sha256) || !seen.insert(a.path.as_str())
            })
        {
            findings.push(Finding::InvalidAuxiliary);
        }
    }
    for candidate in [
        draft.case_authorization_ref.as_ref(),
        draft.approved_target_ref.as_ref(),
        draft.capture_policy_ref.as_ref(),
        draft.cleanup_receipt_ref.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if !safe_reference(candidate) {
            findings.push(Finding::InvalidReference);
        }
    }
    if let Some(b) = draft.fixed_resource_budget
        && (b.max_attempts != MAX_ATTEMPTS
            || b.timeout_ms == 0
            || b.timeout_ms > MAX_DRAFT_TIMEOUT_MS
            || b.max_stdout_bytes == 0
            || b.max_stdout_bytes > MAX_DRAFT_OUTPUT_BYTES
            || b.max_stderr_bytes == 0
            || b.max_stderr_bytes > MAX_DRAFT_OUTPUT_BYTES)
    {
        findings.push(Finding::InvalidBudget);
    }

    let observations_ok = observed.len() == def.required_preconditions.len()
        && observed.iter().all(|(name, value)| {
            def.required_preconditions.contains(name) && *value == Observation::True
        })
        && observed.iter().map(|x| x.0).collect::<BTreeSet<_>>().len() == observed.len();
    if !observations_ok {
        findings.push(Finding::UnmetPreconditions);
    }

    // Fail closed on ALL paths; even an entirely well-formed draft is not executable.
    findings.push(Finding::AuthorizationUnavailable);
    Review {
        decision: Decision::BlockedUnboundNoExecution,
        dispatch_allowed: false,
        authorized: false,
        findings,
    }
}
