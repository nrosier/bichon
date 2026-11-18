//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Stored SSO configuration: the document the SSO settings UI edits.
//!
//! It lives in `system_config` (encrypted) under [`STORAGE_KEY`] and, when
//! present, overrides the UI-managed `BICHON_OIDC_*` values. The secret never
//! leaves this module in any readable form except through
//! [`SsoStoredConfig::client_secret`] itself: [`Debug`] redacts it and
//! [`SsoConfigView`] only reports whether one is set.

use std::fmt;
use std::sync::{LazyLock, RwLock};

use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

use super::config::{check_issuer_url, check_redirect_uri};
use crate::error::BichonResult;
use crate::system_config;

/// `system_config` key holding the JSON document.
pub const STORAGE_KEY: &str = "oidc.sso_config";

/// Placeholder a client sends back for a secret it never saw.
pub const SECRET_MASK: &str = "********";

const MAX_DOMAIN_LEN: usize = 253;

/// The persisted SSO document.
#[derive(Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SsoStoredConfig {
    pub enabled: bool,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
    /// UTC milliseconds of the last save.
    #[serde(default)]
    pub updated_at: i64,
}

impl fmt::Debug for SsoStoredConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SsoStoredConfig")
            .field("enabled", &self.enabled)
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("redirect_uri", &self.redirect_uri)
            .field("allowed_email_domains", &self.allowed_email_domains)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

fn non_empty(v: &Option<String>) -> bool {
    v.as_deref().is_some_and(|s| !s.trim().is_empty())
}

impl SsoStoredConfig {
    /// Issuer, client id and redirect URI are all present. The secret is not
    /// required: public PKCE clients have none.
    pub fn is_configured(&self) -> bool {
        non_empty(&self.issuer_url) && non_empty(&self.client_id) && non_empty(&self.redirect_uri)
    }

    /// The GET response. `active` is whether login is actually usable now.
    pub fn to_view(&self, active: bool) -> SsoConfigView {
        SsoConfigView {
            enabled: self.enabled,
            issuer_url: self.issuer_url.clone(),
            client_id: self.client_id.clone(),
            client_secret_set: non_empty(&self.client_secret),
            redirect_uri: self.redirect_uri.clone(),
            allowed_email_domains: self.allowed_email_domains.clone(),
            configured: self.is_configured(),
            active,
            updated_at: self.updated_at,
        }
    }
}

/// View of the configuration for the UI. Contains no secret.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SsoConfigView {
    pub enabled: bool,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret_set: bool,
    pub redirect_uri: Option<String>,
    pub allowed_email_domains: Vec<String>,
    pub configured: bool,
    pub active: bool,
    pub updated_at: i64,
}

/// View for an install with nothing stored and nothing in the environment.
pub fn empty_view(active: bool) -> SsoConfigView {
    SsoStoredConfig::default().to_view(active)
}

/// Absent keeps, `null` clears, a value replaces.
#[derive(Clone, Debug, PartialEq, Default)]
pub enum Patch<T> {
    #[default]
    Keep,
    Clear,
    Set(T),
}

fn patch<'de, D, T>(d: D) -> Result<Patch<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(match Option::<T>::deserialize(d)? {
        None => Patch::Clear,
        Some(v) => Patch::Set(v),
    })
}

/// What to do with the client secret.
#[derive(Clone, PartialEq, Default)]
pub enum SecretUpdate {
    /// Absent, `null`, or the `"********"` mask.
    #[default]
    Keep,
    /// Empty string.
    Clear,
    Replace(String),
}

impl fmt::Debug for SecretUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keep => f.write_str("Keep"),
            Self::Clear => f.write_str("Clear"),
            Self::Replace(_) => f.write_str("Replace(<redacted>)"),
        }
    }
}

fn secret_update<'de, D: Deserializer<'de>>(d: D) -> Result<SecretUpdate, D::Error> {
    Ok(match Option::<String>::deserialize(d)? {
        None => SecretUpdate::Keep,
        Some(s) if s == SECRET_MASK => SecretUpdate::Keep,
        Some(s) if s.is_empty() => SecretUpdate::Clear,
        Some(s) => SecretUpdate::Replace(s),
    })
}

/// The PUT body. Every field is optional; absent means keep.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct SsoUpdate {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default, deserialize_with = "patch")]
    pub issuer_url: Patch<String>,
    #[serde(default, deserialize_with = "patch")]
    pub client_id: Patch<String>,
    #[serde(default, deserialize_with = "secret_update")]
    pub client_secret: SecretUpdate,
    #[serde(default, deserialize_with = "patch")]
    pub redirect_uri: Patch<String>,
    /// `null` clears the list.
    #[serde(default, deserialize_with = "patch")]
    pub allowed_email_domains: Patch<Vec<String>>,
}

/// A rejected update, naming the offending field.
#[derive(Clone, Debug, PartialEq)]
pub struct SsoValidationError {
    pub field: &'static str,
    pub message: String,
}

impl SsoValidationError {
    fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }
}

impl fmt::Display for SsoValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for SsoValidationError {}

/// Merge `update` into the stored document and validate the result.
///
/// With no stored document, `effective` (the env-derived config) is the base.
pub fn apply_update(
    current: Option<&SsoStoredConfig>,
    effective: &SsoStoredConfig,
    update: SsoUpdate,
    now_ms: i64,
) -> Result<SsoStoredConfig, SsoValidationError> {
    let allow_insecure = super::config::allow_insecure_issuer().unwrap_or(false);
    let expected_path =
        super::config::callback_path(&crate::settings::cli::SETTINGS.bichon_base_url);
    apply_update_with(current, effective, update, now_ms, allow_insecure, &expected_path)
}

fn apply_update_with(
    current: Option<&SsoStoredConfig>,
    effective: &SsoStoredConfig,
    update: SsoUpdate,
    now_ms: i64,
    allow_insecure: bool,
    expected_path: &str,
) -> Result<SsoStoredConfig, SsoValidationError> {
    let mut cfg = current.unwrap_or(effective).clone();

    if let Some(enabled) = update.enabled {
        cfg.enabled = enabled;
    }
    apply_text(&mut cfg.issuer_url, update.issuer_url);
    apply_text(&mut cfg.client_id, update.client_id);
    apply_text(&mut cfg.redirect_uri, update.redirect_uri);
    match update.client_secret {
        SecretUpdate::Keep => {}
        SecretUpdate::Clear => cfg.client_secret = None,
        SecretUpdate::Replace(s) => cfg.client_secret = Some(s),
    }
    match update.allowed_email_domains {
        Patch::Keep => {}
        Patch::Clear => cfg.allowed_email_domains.clear(),
        Patch::Set(list) => cfg.allowed_email_domains = normalize_domains(&list)?,
    }

    if let Some(issuer) = cfg.issuer_url.as_deref() {
        check_issuer_url(issuer, allow_insecure)
            .map_err(|e| SsoValidationError::new("issuer_url", e.to_string()))?;
    }
    if let Some(redirect) = cfg.redirect_uri.as_deref() {
        let url = Url::parse(redirect).map_err(|e| {
            SsoValidationError::new("redirect_uri", format!("must be an absolute URL: {e}"))
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(SsoValidationError::new(
                "redirect_uri",
                "must be an http(s) URL",
            ));
        }
        // A path mismatch only warns; hard failures were handled above.
        check_redirect_uri(redirect, expected_path)
            .map_err(|e| SsoValidationError::new("redirect_uri", e.to_string()))?;
    }

    if cfg.enabled {
        for (field, present) in [
            ("issuer_url", non_empty(&cfg.issuer_url)),
            ("client_id", non_empty(&cfg.client_id)),
            ("redirect_uri", non_empty(&cfg.redirect_uri)),
        ] {
            if !present {
                return Err(SsoValidationError::new(
                    field,
                    "required to enable single sign-on",
                ));
            }
        }
    }

    cfg.updated_at = now_ms;
    Ok(cfg)
}

/// Trim; a blank value clears.
fn apply_text(slot: &mut Option<String>, patch: Patch<String>) {
    match patch {
        Patch::Keep => {}
        Patch::Clear => *slot = None,
        Patch::Set(v) => {
            let v = v.trim();
            *slot = (!v.is_empty()).then(|| v.to_owned());
        }
    }
}

fn normalize_domains(list: &[String]) -> Result<Vec<String>, SsoValidationError> {
    let mut out: Vec<String> = Vec::with_capacity(list.len());
    for raw in list {
        let d = raw.trim().to_ascii_lowercase();
        let d = d.strip_prefix('@').unwrap_or(&d).trim_end_matches('.');
        let bad = |why: &str| {
            SsoValidationError::new(
                "allowed_email_domains",
                format!("invalid domain '{raw}': {why}"),
            )
        };
        if d.is_empty() {
            return Err(bad("empty"));
        }
        if d.len() > MAX_DOMAIN_LEN {
            return Err(bad("longer than 253 characters"));
        }
        if !d
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        {
            return Err(bad("only letters, digits, '.' and '-' are allowed"));
        }
        if d.starts_with(['-', '.']) || d.ends_with('-') || d.contains("..") {
            return Err(bad("malformed"));
        }
        if !out.iter().any(|e| e == d) {
            out.push(d.to_owned());
        }
    }
    Ok(out)
}

// -- storage ---------------------------------------------------------------

/// `None` = not loaded yet; `Some(None)` = loaded, nothing stored.
static CACHED: LazyLock<RwLock<Option<Option<SsoStoredConfig>>>> =
    LazyLock::new(|| RwLock::new(None));

/// The stored document, if any. Cached after the first read.
pub fn load_stored() -> Option<SsoStoredConfig> {
    if let Some(hit) = CACHED.read().unwrap().as_ref() {
        return hit.clone();
    }
    let doc = read_store();
    *CACHED.write().unwrap() = Some(doc.clone());
    doc
}

fn read_store() -> Option<SsoStoredConfig> {
    let raw = system_config::get(STORAGE_KEY)?;
    match serde_json::from_str::<SsoStoredConfig>(&raw) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            // The error carries no document text, so the secret is not logged.
            tracing::error!("oidc: stored SSO config is invalid ({e}); using environment");
            None
        }
    }
}

/// Persist `cfg` and make it visible to the next `OidcConfig::load()`.
pub fn save_stored(cfg: &SsoStoredConfig) -> BichonResult<()> {
    let json = serde_json::to_string(cfg).map_err(|e| {
        crate::raise_error!(
            format!("failed to serialize SSO config: {e}"),
            crate::error::code::ErrorCode::InternalError
        )
    })?;
    system_config::set(STORAGE_KEY, &json)?;
    *CACHED.write().unwrap() = Some(Some(cfg.clone()));
    Ok(())
}

/// Drop the cache so the next read goes to the store.
pub fn invalidate_stored_cache() {
    *CACHED.write().unwrap() = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "/api/auth/oidc/callback";

    fn base() -> SsoStoredConfig {
        SsoStoredConfig {
            enabled: false,
            issuer_url: Some("https://idp.example.com".into()),
            client_id: Some("bichon".into()),
            client_secret: Some("s3cr3t-value".into()),
            redirect_uri: Some("https://mail.example.com/api/auth/oidc/callback".into()),
            allowed_email_domains: vec![],
            updated_at: 0,
        }
    }

    fn apply(update: SsoUpdate) -> Result<SsoStoredConfig, SsoValidationError> {
        apply_update_with(Some(&base()), &SsoStoredConfig::default(), update, 5, false, PATH)
    }

    fn domains(list: &[&str]) -> Result<Vec<String>, SsoValidationError> {
        normalize_domains(&list.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let out = format!("{:?}", base());
        assert!(!out.contains("s3cr3t-value"), "{out}");
        assert!(out.contains("<redacted>"));
        let upd = format!("{:?}", SecretUpdate::Replace("s3cr3t-value".into()));
        assert!(!upd.contains("s3cr3t-value"));
    }

    #[test]
    fn view_hides_secret_and_reports_presence() {
        let json = serde_json::to_string(&base().to_view(true)).unwrap();
        assert!(!json.contains("s3cr3t-value"), "{json}");
        assert!(json.contains("\"client_secret_set\":true"));
        assert!(base().to_view(false).client_secret_set);
        for secret in [None, Some(String::new())] {
            let cfg = SsoStoredConfig {
                client_secret: secret,
                ..base()
            };
            assert!(!cfg.to_view(false).client_secret_set);
        }
        let v = empty_view(false);
        assert!(!v.configured && v.updated_at == 0);
        assert!(base().to_view(false).configured);
    }

    #[test]
    fn domains_are_normalized() {
        assert_eq!(domains(&["@Example.COM."]).unwrap(), vec!["example.com"]);
        assert_eq!(
            domains(&["a.com", "B.com", "@a.com."]).unwrap(),
            vec!["a.com", "b.com"]
        );
    }

    #[test]
    fn bad_domains_are_rejected() {
        let too_long = "a".repeat(254);
        for bad in ["a..b", "-x.com", "x.com-", ".x.com", "ex_ample.com", "", "@", &too_long] {
            let err = domains(&[bad]).unwrap_err();
            assert_eq!(err.field, "allowed_email_domains", "{bad:?}");
        }
        assert!(domains(&[&"a".repeat(253)]).is_ok());
    }

    #[test]
    fn secret_cases() {
        let parse = |j: &str| serde_json::from_str::<SsoUpdate>(j).unwrap();
        assert_eq!(apply(parse("{}")).unwrap().client_secret.as_deref(), Some("s3cr3t-value"));
        assert_eq!(
            apply(parse(r#"{"client_secret":"********"}"#)).unwrap().client_secret.as_deref(),
            Some("s3cr3t-value")
        );
        assert_eq!(apply(parse(r#"{"client_secret":""}"#)).unwrap().client_secret, None);
        assert_eq!(
            apply(parse(r#"{"client_secret":"new"}"#)).unwrap().client_secret.as_deref(),
            Some("new")
        );
    }

    #[test]
    fn absent_keeps_and_null_clears() {
        let parse = |j: &str| serde_json::from_str::<SsoUpdate>(j).unwrap();
        let kept = apply(parse(r#"{"enabled":false}"#)).unwrap();
        assert_eq!(kept.issuer_url, base().issuer_url);
        assert_eq!(kept.updated_at, 5);
        let cleared = apply(parse(r#"{"client_id":null,"allowed_email_domains":null}"#)).unwrap();
        assert_eq!(cleared.client_id, None);
        assert!(cleared.allowed_email_domains.is_empty());
    }

    #[test]
    fn no_stored_document_starts_from_effective() {
        let upd = SsoUpdate {
            enabled: Some(true),
            ..Default::default()
        };
        let out = apply_update_with(None, &base(), upd, 9, false, PATH).unwrap();
        assert!(out.enabled);
        assert_eq!(out.client_id.as_deref(), Some("bichon"));
    }

    #[test]
    fn enabling_requires_configuration() {
        let upd = SsoUpdate {
            enabled: Some(true),
            ..Default::default()
        };
        let err = apply_update_with(None, &SsoStoredConfig::default(), upd, 1, false, PATH)
            .unwrap_err();
        assert_eq!(err.field, "issuer_url");
        // No secret is fine (public client).
        let ok = apply(SsoUpdate {
            enabled: Some(true),
            client_secret: SecretUpdate::Clear,
            ..Default::default()
        });
        assert!(ok.is_ok());
    }

    #[test]
    fn insecure_issuer_needs_opt_in() {
        let upd = || SsoUpdate {
            issuer_url: Patch::Set("http://192.168.1.10:9000".into()),
            ..Default::default()
        };
        let run = |allow| apply_update_with(Some(&base()), &base(), upd(), 1, allow, PATH);
        assert_eq!(run(false).unwrap_err().field, "issuer_url");
        assert!(run(true).is_ok());
        let loopback = SsoUpdate {
            issuer_url: Patch::Set("http://localhost:9000".into()),
            ..Default::default()
        };
        assert!(apply(loopback).is_ok());
    }

    #[test]
    fn redirect_uri_must_be_absolute_http() {
        for bad in ["/cb", "javascript:alert(1)"] {
            let err = apply(SsoUpdate {
                redirect_uri: Patch::Set(bad.into()),
                ..Default::default()
            })
            .unwrap_err();
            assert_eq!(err.field, "redirect_uri", "{bad}");
        }
        // Wrong path is a warning only.
        assert!(apply(SsoUpdate {
            redirect_uri: Patch::Set("https://mail.example.com/".into()),
            ..Default::default()
        })
        .is_ok());
    }
}
