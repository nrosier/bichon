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

//! ID token verification: signature first, then claims.
//!
//! Only the algorithms in [`SigningAlg`] are accepted. `none` and anything
//! else is rejected before a key is even looked up, and the key type found in
//! the JWKS must belong to the same family as the header's `alg`, so a token
//! cannot talk Bichon into verifying an RSA signature as an HMAC (the classic
//! algorithm-confusion attack).

use base64::engine::general_purpose::URL_SAFE_NO_PAD_INDIFFERENT;
use base64::Engine;
use ring::hmac;
use ring::signature::{
    RsaPublicKeyComponents, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use crate::error::code::ErrorCode;
use crate::error::{BichonError, BichonResult};
use crate::oidc::config::OidcConfig;
use crate::oidc::jwks::{self, Jwk};
use crate::raise_error;
use crate::utc_now;

/// Tolerance applied to `exp` and `iat` to absorb clock skew between Bichon and
/// the IdP. Documented in the README as 60 s.
pub const CLOCK_SKEW_SECONDS: i64 = 60;

/// The signature algorithms Bichon will verify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningAlg {
    Rs256,
    Rs384,
    Rs512,
    Es256,
    Hs256,
}

impl SigningAlg {
    /// Parse the header's `alg`. Every value outside the allow-list — including
    /// `none` — is an error rather than a fallback.
    fn parse(alg: &str) -> BichonResult<Self> {
        match alg {
            "RS256" => Ok(Self::Rs256),
            "RS384" => Ok(Self::Rs384),
            "RS512" => Ok(Self::Rs512),
            "ES256" => Ok(Self::Es256),
            "HS256" => Ok(Self::Hs256),
            "none" | "None" | "NONE" => Err(raise_error!(
                "The ID token is unsigned (alg=none); unsigned tokens are never accepted.".into(),
                ErrorCode::PermissionDenied
            )),
            other => Err(raise_error!(
                format!(
                    "The ID token is signed with '{}', which Bichon does not accept. Supported algorithms: RS256, RS384, RS512, ES256, HS256.",
                    other
                ),
                ErrorCode::PermissionDenied
            )),
        }
    }

    /// The `kty` a JWKS entry must have to be usable with this algorithm.
    fn expected_kty(&self) -> &'static str {
        match self {
            Self::Rs256 | Self::Rs384 | Self::Rs512 => "RSA",
            Self::Es256 => "EC",
            // Symmetric: the key is the client secret, never a JWKS entry.
            Self::Hs256 => "oct",
        }
    }

    fn is_symmetric(&self) -> bool {
        matches!(self, Self::Hs256)
    }
}

/// The JOSE header members Bichon reads.
#[derive(Clone, Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// `aud` is either a single string or an array of strings (RFC 7519 §4.1.3).
#[derive(Clone, Debug, Serialize)]
pub struct Audience(pub Vec<String>);

impl Audience {
    pub fn contains(&self, value: &str) -> bool {
        self.0.iter().any(|a| a == value)
    }
}

impl<'de> Deserialize<'de> for Audience {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            One(String),
            Many(Vec<String>),
        }
        match Raw::deserialize(deserializer)? {
            Raw::One(single) => Ok(Audience(vec![single])),
            Raw::Many(many) if many.is_empty() => {
                Err(de::Error::custom("the 'aud' claim is an empty array"))
            }
            Raw::Many(many) => Ok(Audience(many)),
        }
    }
}

/// The ID token claims Bichon uses. Provider-specific extras are ignored.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IdTokenClaims {
    pub iss: String,
    /// Stable, provider-unique identifier for the end user. Persisted as
    /// [`crate::users::BichonUserV2::sso_id`].
    pub sub: String,
    pub aud: Audience,
    /// Expiry, seconds since the epoch.
    pub exp: i64,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(default)]
    pub nonce: Option<String>,
    /// Authorized party. Required by the spec when `aud` has multiple values.
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    /// Whether the provider vouches for the address in `email`. Consulted by
    /// [`crate::oidc::user`] before an email is allowed to adopt an existing
    /// account.
    #[serde(default, deserialize_with = "lenient_bool")]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Session id, used for RP-initiated logout when the provider supplies it.
    #[serde(default)]
    pub sid: Option<String>,
}

/// Deserialise a claim that ought to be a boolean but is not always one.
///
/// `email_verified` is specified as a boolean, yet providers have shipped it as
/// the string `"true"` for years. A plain `Option<bool>` would make such a token
/// fail to parse — turning a cosmetic provider quirk into a login that cannot
/// happen at all — so a string is read and anything else becomes `None`.
///
/// `None` means "the provider said nothing usable", which every caller must treat
/// as *not* verified. Being lenient about the shape is safe only because being
/// strict about the meaning happens elsewhere.
pub(crate) fn lenient_bool<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<bool>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Bool(bool),
        Text(String),
        /// Numbers, objects, arrays: accepted rather than rejected, then dropped.
        Other(serde::de::IgnoredAny),
    }

    Ok(match Option::<Raw>::deserialize(deserializer)? {
        None | Some(Raw::Other(_)) => None,
        Some(Raw::Bool(value)) => Some(value),
        Some(Raw::Text(text)) => match text.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
    })
}

/// Verify an ID token end to end.
///
/// `expected_nonce` is the value Bichon generated when it built the
/// authorization request; a mismatch means the token is being replayed.
pub async fn verify_id_token(
    token: &str,
    config: &OidcConfig,
    jwks_uri: &str,
    expected_nonce: &str,
) -> BichonResult<IdTokenClaims> {
    let (header, signing_input, signature) = split(token)?;
    let alg = SigningAlg::parse(&header.alg)?;

    if alg.is_symmetric() {
        let secret = config.client_secret.as_deref().ok_or_else(|| {
            raise_error!(
                "The ID token is signed with HS256 but BICHON_OIDC_CLIENT_SECRET is not set, so the signature cannot be verified."
                    .into(),
                ErrorCode::MissingConfiguration
            )
        })?;
        verify_hmac(secret, signing_input.as_bytes(), &signature)?;
    } else {
        let key = jwks::signing_key(jwks_uri, header.kid.as_deref()).await?;
        verify_asymmetric(alg, &key, signing_input.as_bytes(), &signature)?;
    }

    // Claims are only parsed once the signature holds, so unverified input never
    // reaches the rest of the login path.
    let claims = decode_claims(token)?;
    validate_claims(&claims, config, expected_nonce)?;
    Ok(claims)
}

/// Split a compact JWS into its header, signing input and signature.
fn split(token: &str) -> BichonResult<(JwtHeader, &str, Vec<u8>)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() == 5 {
        return Err(raise_error!(
            "The ID token is encrypted (JWE). Configure the provider to issue a signed, unencrypted ID token."
                .into(),
            ErrorCode::PermissionDenied
        ));
    }
    if parts.len() != 3 {
        return Err(raise_error!(
            "The ID token is not a valid JWT (expected three dot-separated segments).".into(),
            ErrorCode::PermissionDenied
        ));
    }
    if parts.iter().any(|p| p.is_empty()) {
        return Err(raise_error!(
            "The ID token has an empty segment; unsigned or truncated tokens are rejected.".into(),
            ErrorCode::PermissionDenied
        ));
    }

    let header_bytes = b64(parts[0], "header")?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes).map_err(|e| {
        raise_error!(
            format!("The ID token header could not be parsed: {}", e),
            ErrorCode::PermissionDenied
        )
    })?;

    let signature = b64(parts[2], "signature")?;
    // The signature covers exactly "<header>.<payload>" as it appeared on the wire.
    let signing_input = &token[..parts[0].len() + 1 + parts[1].len()];

    Ok((header, signing_input, signature))
}

fn decode_claims(token: &str) -> BichonResult<IdTokenClaims> {
    let payload = token.split('.').nth(1).ok_or_else(|| {
        raise_error!(
            "The ID token has no payload segment.".into(),
            ErrorCode::PermissionDenied
        )
    })?;
    let bytes = b64(payload, "payload")?;
    serde_json::from_slice(&bytes).map_err(|e| {
        raise_error!(
            format!("The ID token claims could not be parsed: {}", e),
            ErrorCode::PermissionDenied
        )
    })
}

fn verify_hmac(secret: &str, message: &[u8], signature: &[u8]) -> BichonResult<()> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    hmac::verify(&key, message, signature).map_err(|_| bad_signature())
}

fn verify_asymmetric(
    alg: SigningAlg,
    key: &Jwk,
    message: &[u8],
    signature: &[u8],
) -> BichonResult<()> {
    // Guard against algorithm confusion: the header cannot select a key family
    // different from the one the published key actually belongs to.
    if key.kty != alg.expected_kty() {
        return Err(raise_error!(
            format!(
                "The ID token declares alg '{:?}' but the matching JWKS key is of type '{}'.",
                alg, key.kty
            ),
            ErrorCode::PermissionDenied
        ));
    }

    match alg {
        SigningAlg::Rs256 | SigningAlg::Rs384 | SigningAlg::Rs512 => {
            let n = b64(component(&key.n, "n")?, "JWKS RSA modulus")?;
            let e = b64(component(&key.e, "e")?, "JWKS RSA exponent")?;
            let params = match alg {
                SigningAlg::Rs256 => &RSA_PKCS1_2048_8192_SHA256,
                SigningAlg::Rs384 => &RSA_PKCS1_2048_8192_SHA384,
                _ => &RSA_PKCS1_2048_8192_SHA512,
            };
            RsaPublicKeyComponents { n, e }
                .verify(params, message, signature)
                .map_err(|_| bad_signature())
        }
        SigningAlg::Es256 => {
            let crv = key.crv.as_deref().unwrap_or_default();
            if crv != "P-256" {
                return Err(raise_error!(
                    format!(
                        "ES256 requires a P-256 key but the JWKS entry uses curve '{}'.",
                        crv
                    ),
                    ErrorCode::PermissionDenied
                ));
            }
            let x = coordinate(component(&key.x, "x")?, "x")?;
            let y = coordinate(component(&key.y, "y")?, "y")?;
            // SEC1 uncompressed point: 0x04 || X || Y.
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                .verify(message, signature)
                .map_err(|_| bad_signature())
        }
        SigningAlg::Hs256 => unreachable!("symmetric algorithms are handled by verify_hmac"),
    }
}

fn validate_claims(
    claims: &IdTokenClaims,
    config: &OidcConfig,
    expected_nonce: &str,
) -> BichonResult<()> {
    if claims.iss.trim_end_matches('/') != config.issuer_url {
        return Err(raise_error!(
            format!(
                "The ID token was issued by '{}' but the configured issuer is '{}'.",
                claims.iss, config.issuer_url
            ),
            ErrorCode::PermissionDenied
        ));
    }

    if !claims.aud.contains(&config.client_id) {
        return Err(raise_error!(
            format!(
                "The ID token audience {:?} does not include this client ('{}').",
                claims.aud.0, config.client_id
            ),
            ErrorCode::PermissionDenied
        ));
    }

    // OIDC Core §3.1.3.7 (4): with several audiences the token must name the
    // authorized party, and it has to be us.
    if claims.aud.0.len() > 1 {
        match claims.azp.as_deref() {
            Some(azp) if azp == config.client_id => {}
            Some(azp) => {
                return Err(raise_error!(
                    format!(
                        "The ID token authorizes party '{}', not this client ('{}').",
                        azp, config.client_id
                    ),
                    ErrorCode::PermissionDenied
                ));
            }
            None => {
                return Err(raise_error!(
                    "The ID token lists multiple audiences but omits the 'azp' claim.".into(),
                    ErrorCode::PermissionDenied
                ));
            }
        }
    }

    let now = utc_now!() / 1000;
    if claims.exp <= now - CLOCK_SKEW_SECONDS {
        return Err(raise_error!(
            "The ID token has expired. Please try signing in again.".into(),
            ErrorCode::PermissionDenied
        ));
    }
    if let Some(iat) = claims.iat {
        if iat > now + CLOCK_SKEW_SECONDS {
            return Err(raise_error!(
                "The ID token is issued in the future; check that the clocks of Bichon and the identity provider agree."
                    .into(),
                ErrorCode::PermissionDenied
            ));
        }
    }

    if claims.sub.trim().is_empty() {
        return Err(raise_error!(
            "The ID token has an empty 'sub' claim, so the user cannot be identified.".into(),
            ErrorCode::PermissionDenied
        ));
    }

    // The nonce ties this token to the authorization request Bichon started.
    // Compared in constant time: the value is a secret for the length of the flow.
    let nonce = claims.nonce.as_deref().ok_or_else(|| {
        raise_error!(
            "The ID token is missing the 'nonce' claim, so it cannot be tied to this login attempt."
                .into(),
            ErrorCode::PermissionDenied
        )
    })?;
    if !constant_time_eq(nonce.as_bytes(), expected_nonce.as_bytes()) {
        return Err(raise_error!(
            "The ID token nonce does not match this login attempt.".into(),
            ErrorCode::PermissionDenied
        ));
    }

    Ok(())
}

/// Compare two byte strings without an early exit on the first difference.
///
/// Only the length is allowed to leak, which is not a secret here: both values
/// are fixed-length generated tokens.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // Keep the optimiser from turning the fold back into a short-circuit.
    std::hint::black_box(diff) == 0
}

/// Deliberately uniform for every signature failure: the caller learns that
/// verification failed, not which step of it did.
fn bad_signature() -> BichonError {
    raise_error!(
        "The ID token signature is not valid.".into(),
        ErrorCode::PermissionDenied
    )
}

fn component<'a>(value: &'a Option<String>, name: &str) -> BichonResult<&'a str> {
    value.as_deref().ok_or_else(|| {
        raise_error!(
            format!("The JWKS key is missing the '{}' parameter.", name),
            ErrorCode::PermissionDenied
        )
    })
}

/// Normalise an EC coordinate to the 32 bytes P-256 requires.
///
/// RFC 7518 §6.2.1.2 mandates fixed-length coordinates, but some providers strip
/// leading zero bytes, so short values are left-padded rather than rejected.
fn coordinate(value: &str, name: &str) -> BichonResult<[u8; 32]> {
    let bytes = b64(value, "JWKS EC coordinate")?;
    if bytes.len() > 32 {
        return Err(raise_error!(
            format!(
                "The JWKS EC coordinate '{}' is {} bytes, which is too large for P-256.",
                name,
                bytes.len()
            ),
            ErrorCode::PermissionDenied
        ));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

/// Decode a base64url segment. JWTs are unpadded, but padding is tolerated
/// because a few providers emit it in their JWKS values.
fn b64(value: &str, what: &str) -> BichonResult<Vec<u8>> {
    URL_SAFE_NO_PAD_INDIFFERENT.decode(value).map_err(|e| {
        raise_error!(
            format!("The {} is not valid base64url: {}", what, e),
            ErrorCode::PermissionDenied
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    const SECRET: &str = "a-test-client-secret-value";
    const ISSUER: &str = "https://idp.example.com";
    const CLIENT_ID: &str = "bichon";
    const NONCE: &str = "nonce-from-the-pending-request";
    const JWKS_URI: &str = "https://idp.example.com/jwks";

    fn config() -> OidcConfig {
        OidcConfig {
            issuer_url: ISSUER.into(),
            client_id: CLIENT_ID.into(),
            client_secret: Some(SECRET.into()),
            redirect_uri: "https://mail.example.com/api/auth/oidc/callback".into(),
            default_role_id: 100_200_000_000_000,
            auto_redirect: false,
            link_by_email: false,
        }
    }

    fn now() -> i64 {
        utc_now!() / 1000
    }

    /// Build an HS256-signed token from a claims object.
    fn hs256(claims: serde_json::Value) -> String {
        signed(json!({"alg": "HS256", "typ": "JWT"}), claims)
    }

    fn signed(header: serde_json::Value, claims: serde_json::Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let key = hmac::Key::new(hmac::HMAC_SHA256, SECRET.as_bytes());
        let tag = hmac::sign(&key, input.as_bytes());
        format!("{}.{}", input, URL_SAFE_NO_PAD.encode(tag.as_ref()))
    }

    fn valid_claims() -> serde_json::Value {
        json!({
            "iss": ISSUER,
            "sub": "user-1234",
            "aud": CLIENT_ID,
            "exp": now() + 300,
            "iat": now(),
            "nonce": NONCE,
            "email": "alice@example.com",
            "preferred_username": "alice",
        })
    }

    async fn verify(token: &str) -> BichonResult<IdTokenClaims> {
        verify_id_token(token, &config(), JWKS_URI, NONCE).await
    }

    #[tokio::test]
    async fn accepts_a_valid_hs256_token() {
        let claims = verify(&hs256(valid_claims())).await.unwrap();
        assert_eq!(claims.sub, "user-1234");
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(claims.preferred_username.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn rejects_a_tampered_signature() {
        let token = hs256(valid_claims());
        // Flip the last character of the signature.
        let mut chars: Vec<char> = token.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(verify(&tampered).await.is_err());
    }

    #[tokio::test]
    async fn rejects_a_tampered_payload() {
        // Re-encode the payload with an elevated subject but keep the old signature.
        let token = hs256(valid_claims());
        let parts: Vec<&str> = token.split('.').collect();
        let mut claims = valid_claims();
        claims["sub"] = json!("someone-else");
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(claims.to_string()),
            parts[2]
        );
        assert!(verify(&forged).await.is_err());
    }

    #[tokio::test]
    async fn rejects_alg_none() {
        let header = json!({"alg": "none", "typ": "JWT"});
        let unsigned = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(valid_claims().to_string())
        );
        let err = verify(&unsigned).await.unwrap_err();
        assert!(err.to_string().contains("empty segment"), "{}", err);

        // Also reject alg=none carrying a bogus non-empty signature.
        let with_garbage = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(valid_claims().to_string()),
            URL_SAFE_NO_PAD.encode("not-a-signature")
        );
        let err = verify(&with_garbage).await.unwrap_err();
        assert!(err.to_string().contains("unsigned"), "{}", err);
    }

    #[tokio::test]
    async fn rejects_an_unsupported_algorithm() {
        // A symmetric key cannot be smuggled in under an unsupported name.
        let token = signed(json!({"alg": "HS512", "typ": "JWT"}), valid_claims());
        let err = verify(&token).await.unwrap_err();
        assert!(err.to_string().contains("HS512"), "{}", err);
    }

    #[tokio::test]
    async fn rejects_an_expired_token() {
        let mut claims = valid_claims();
        claims["exp"] = json!(now() - 3600);
        let err = verify(&hs256(claims)).await.unwrap_err();
        assert!(err.to_string().contains("expired"), "{}", err);
    }

    #[tokio::test]
    async fn accepts_a_token_that_just_expired_within_the_skew() {
        let mut claims = valid_claims();
        claims["exp"] = json!(now() - (CLOCK_SKEW_SECONDS - 5));
        assert!(verify(&hs256(claims)).await.is_ok());
    }

    #[tokio::test]
    async fn rejects_a_foreign_issuer() {
        let mut claims = valid_claims();
        claims["iss"] = json!("https://evil.example.com");
        let err = verify(&hs256(claims)).await.unwrap_err();
        assert!(err.to_string().contains("issued by"), "{}", err);
    }

    #[tokio::test]
    async fn tolerates_a_trailing_slash_on_the_issuer() {
        let mut claims = valid_claims();
        claims["iss"] = json!(format!("{}/", ISSUER));
        assert!(verify(&hs256(claims)).await.is_ok());
    }

    #[tokio::test]
    async fn rejects_a_foreign_audience() {
        let mut claims = valid_claims();
        claims["aud"] = json!("another-client");
        let err = verify(&hs256(claims)).await.unwrap_err();
        assert!(err.to_string().contains("audience"), "{}", err);
    }

    #[tokio::test]
    async fn accepts_an_audience_array_containing_the_client() {
        let mut claims = valid_claims();
        claims["aud"] = json!([CLIENT_ID]);
        assert!(verify(&hs256(claims)).await.is_ok());
    }

    #[tokio::test]
    async fn requires_azp_when_several_audiences_are_present() {
        let mut claims = valid_claims();
        claims["aud"] = json!([CLIENT_ID, "other-client"]);
        let err = verify(&hs256(claims.clone())).await.unwrap_err();
        assert!(err.to_string().contains("azp"), "{}", err);

        claims["azp"] = json!("other-client");
        let err = verify(&hs256(claims.clone())).await.unwrap_err();
        assert!(err.to_string().contains("authorizes party"), "{}", err);

        claims["azp"] = json!(CLIENT_ID);
        assert!(verify(&hs256(claims)).await.is_ok());
    }

    #[tokio::test]
    async fn rejects_a_mismatched_nonce() {
        let mut claims = valid_claims();
        claims["nonce"] = json!("some-other-nonce");
        let err = verify(&hs256(claims)).await.unwrap_err();
        assert!(err.to_string().contains("nonce does not match"), "{}", err);
    }

    #[tokio::test]
    async fn rejects_a_missing_nonce() {
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("nonce");
        let err = verify(&hs256(claims)).await.unwrap_err();
        assert!(err.to_string().contains("missing the 'nonce'"), "{}", err);
    }

    #[tokio::test]
    async fn rejects_an_empty_subject() {
        let mut claims = valid_claims();
        claims["sub"] = json!("   ");
        let err = verify(&hs256(claims)).await.unwrap_err();
        assert!(err.to_string().contains("'sub'"), "{}", err);
    }

    #[tokio::test]
    async fn rejects_a_malformed_token() {
        for token in ["", "not-a-jwt", "only.two", "a.b.c.d"] {
            assert!(verify(token).await.is_err(), "accepted {:?}", token);
        }
    }

    #[tokio::test]
    async fn rejects_an_encrypted_token() {
        let err = verify("a.b.c.d.e").await.unwrap_err();
        assert!(err.to_string().contains("encrypted"), "{}", err);
    }

    #[tokio::test]
    async fn rejects_hs256_when_no_client_secret_is_configured() {
        let mut config = config();
        config.client_secret = None;
        let token = hs256(valid_claims());
        let err = verify_id_token(&token, &config, JWKS_URI, NONCE)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("CLIENT_SECRET"), "{}", err);
    }

    /// An RS256 header pointing at an RSA JWKS entry must not be verifiable with
    /// the client secret as an HMAC key.
    #[tokio::test]
    async fn rejects_algorithm_confusion_between_rsa_and_hmac() {
        let jwks_uri = "https://idp.example.com/confusion-jwks";
        jwks::seed_cache(
            jwks_uri,
            jwks::JwkSet {
                keys: vec![Jwk {
                    kty: "RSA".into(),
                    kid: Some("rsa-1".into()),
                    alg: Some("RS256".into()),
                    key_use: Some("sig".into()),
                    // The public modulus of an RSA key, used here as if it were
                    // an HMAC secret by an attacker.
                    n: Some(URL_SAFE_NO_PAD.encode([0xAAu8; 256])),
                    e: Some("AQAB".into()),
                    crv: None,
                    x: None,
                    y: None,
                }],
            },
        )
        .await;

        // HMAC the token with the RSA modulus, then claim it is RS256.
        let header = json!({"alg": "RS256", "typ": "JWT", "kid": "rsa-1"});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(valid_claims().to_string())
        );
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[0xAAu8; 256]);
        let tag = hmac::sign(&key, input.as_bytes());
        let token = format!("{}.{}", input, URL_SAFE_NO_PAD.encode(tag.as_ref()));

        let err = verify_id_token(&token, &config(), jwks_uri, NONCE)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("signature is not valid"), "{}", err);

        jwks::invalidate_cache().await;
    }

    #[test]
    fn ec_coordinates_are_left_padded_to_32_bytes() {
        let short = URL_SAFE_NO_PAD.encode([0x01u8, 0x02]);
        let padded = coordinate(&short, "x").unwrap();
        assert_eq!(padded[30], 0x01);
        assert_eq!(padded[31], 0x02);
        assert!(padded[..30].iter().all(|b| *b == 0));

        let too_long = URL_SAFE_NO_PAD.encode([0u8; 33]);
        assert!(coordinate(&too_long, "x").is_err());
    }

    #[test]
    fn email_verified_reads_the_shapes_providers_actually_send() {
        for (raw, expected) in [
            ("true", Some(true)),
            ("false", Some(false)),
            // The long-standing quirk this leniency exists for.
            ("\"true\"", Some(true)),
            ("\"false\"", Some(false)),
            ("\"TRUE\"", Some(true)),
            ("\" true \"", Some(true)),
        ] {
            let claims = claims_with_email_verified(raw);
            assert_eq!(claims.email_verified, expected, "{}", raw);
        }
    }

    #[test]
    fn email_verified_treats_anything_else_as_no_answer() {
        // None is not "verified": `oidc::user` requires Some(true) exactly. What
        // matters here is that none of these fail the whole token parse, which
        // would break the login rather than just the linking decision.
        for raw in ["null", "1", "0", "\"yes\"", "\"\"", "{}", "[]", "1.5"] {
            let claims = claims_with_email_verified(raw);
            assert_eq!(claims.email_verified, None, "{}", raw);
        }
    }

    #[test]
    fn email_verified_is_absent_without_complaint() {
        let claims: IdTokenClaims = serde_json::from_value(valid_claims()).unwrap();
        assert_eq!(claims.email_verified, None);
    }

    fn claims_with_email_verified(raw: &str) -> IdTokenClaims {
        let mut claims = valid_claims();
        claims["email_verified"] = serde_json::from_str(raw).expect("test fixture must be JSON");
        serde_json::from_value(claims).unwrap_or_else(|e| panic!("{} failed to parse: {}", raw, e))
    }

    #[test]
    fn audience_accepts_both_json_shapes() {
        let one: Audience = serde_json::from_str("\"a\"").unwrap();
        assert_eq!(one.0, vec!["a"]);
        let many: Audience = serde_json::from_str("[\"a\",\"b\"]").unwrap();
        assert_eq!(many.0, vec!["a", "b"]);
        assert!(serde_json::from_str::<Audience>("[]").is_err());
    }

    #[test]
    fn constant_time_eq_matches_ordinary_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn signing_alg_allow_list_is_closed() {
        for good in ["RS256", "RS384", "RS512", "ES256", "HS256"] {
            assert!(SigningAlg::parse(good).is_ok(), "{}", good);
        }
        for bad in ["none", "None", "NONE", "HS384", "HS512", "PS256", "EdDSA", ""] {
            assert!(SigningAlg::parse(bad).is_err(), "{}", bad);
        }
    }
}
