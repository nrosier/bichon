# OpenID Connect (OIDC) Single Sign-On

Bichon can delegate WebUI authentication to any OIDC provider (Authentik,
Keycloak, PocketID, Authelia, Zitadel, Dex, …) using the Authorization Code flow
with PKCE.

> [!NOTE]
> This is a fork-only feature. Upstream Bichon ships SSO in its paid edition, so
> this document — and the code it describes — live in files upstream does not
> have: `crates/core/src/oidc/`, `crates/server/src/rest/oidc/`, and
> `web/src/sso/`. See [Layout](#layout) below.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BICHON_OIDC_ENABLED` | `false` | Master switch for OIDC single sign-on |
| `BICHON_OIDC_ISSUER_URL` | — | Issuer URL. Bichon appends `/.well-known/openid-configuration` for discovery. Example: `https://auth.example.com/application/o/bichon/` |
| `BICHON_OIDC_CLIENT_ID` | — | OAuth2 client ID registered with the IdP |
| `BICHON_OIDC_CLIENT_SECRET` | — | OAuth2 client secret registered with the IdP |
| `BICHON_OIDC_REDIRECT_URI` | `<BICHON_PUBLIC_URL><BICHON_BASE_URL>/api/auth/oidc/callback` | Redirect URI registered with the IdP. Only needed when that derived value is not how the browser reaches Bichon |
| `BICHON_OIDC_DEFAULT_ROLE_ID` | `100200000000000` (Member) | Global role ID assigned to auto-provisioned OIDC users |
| `BICHON_OIDC_AUTO_REDIRECT` | `false` | When true, `/sign-in` skips the choice and goes straight to the IdP. Local login stays reachable via `/sign-in?local=1` |

The first five are fields of Bichon's own `Settings` struct, so they also accept
CLI flags (`--bichon-oidc-issuer-url`) and appear in the settings API.

The last two are **environment-only** — no `--flag` form, and not in the settings
API. They are this fork's own settings, and keeping them out of upstream's
`Settings` struct is what lets `crates/core/src/settings/` stay byte-identical to
upstream. They are read in
[`crates/core/src/oidc/config.rs`](../crates/core/src/oidc/config.rs) instead. A
typo in either is a startup error rather than a silent default, so
`BICHON_OIDC_AUTO_REDIRECT=yes` will not quietly leave auto-redirect off.

## Behaviour

**Sign-in page.** With SSO enabled the sign-in page offers both ways in: the
username/password form and a *Sign in with SSO* button, so local accounts keep
working alongside provider accounts. Set `BICHON_OIDC_AUTO_REDIRECT=true` only if
you want to skip that choice; the form then stays reachable at
`/sign-in?local=1`, and the redirect screen offers the same escape hatch.

If an auto-redirect round trip keeps returning without a session, the page stops
starting new ones by itself (three attempts in two minutes, or an immediate
bounce) and shows the password form with an explanation. A button press is never
rate-limited — only what the page does unprompted.

**User resolution.** On each login Bichon looks up the user by
`(sso_provider, sso_id)` first, then by `email`, and finally auto-provisions a new
user with `BICHON_OIDC_DEFAULT_ROLE_ID`. The `sub` claim from the IdP is stored on
the user and used for subsequent logins.

**Signature verification.** Asymmetric tokens (`RS256`, `RS384`, `RS512`,
`ES256`) are verified against the provider's JWKS, fetched from the `jwks_uri` in
discovery and cached for an hour; an unknown `kid` triggers one re-fetch,
rate-limited so a bad token cannot be used to hammer the provider. `HS256` is
verified with the client secret. Unsigned tokens (`alg: none`) and every other
algorithm are rejected, and the key type must match the algorithm family, so an
RSA key cannot be pressed into service as an HMAC secret. Discovery, issuer,
audience, expiration (with 60 s skew), and nonce are validated; when the token
carries several audiences, `azp` is required.

**Token handoff.** After a successful callback the SPA receives a one-shot handoff
id in the URL and POSTs it to `/api/auth/oidc/handoff` to obtain the WebUI access
token in the response body. The access token itself is never placed in the URL, so
it does not leak into browser history, `Referer` headers, or server access logs.

**Sign-out.** *Sign out of Bichon only* revokes this browser's access token
server-side and keeps the provider session, so signing back in is one click.
*Sign out and end SSO session* additionally performs RP-initiated logout at the
provider. Both revoke server-side first, so clearing local storage is not all
that stands between a copied token and the API.

> [!IMPORTANT]
> `BICHON_OIDC_REDIRECT_URI` and the redirect URI registered with the IdP must be
> the exact same value (including scheme, host, port, and path), and both must
> name Bichon's callback endpoint: `<public-url>/api/auth/oidc/callback`, prefixed
> with `BICHON_BASE_URL` when the UI is served under a sub-path. Behind a reverse
> proxy this is the externally-reachable URL, not `http://localhost:15630`.
>
> Registering the app root (`https://bichon.example.com/`) instead is the common
> mistake: the provider then drops the browser on the WebUI with `?code=…` in the
> query and no session ever gets created. Bichon forwards such a callback to the
> right endpoint and logs a warning naming the value to fix, so sign-in still
> works — but the mismatch is worth correcting.

## Layout

The feature is arranged so that resyncing this fork from upstream conflicts in as
few places as possible. Everything OIDC lives in files upstream does not have:

| Fork-owned | Contents |
|---|---|
| `crates/core/src/oidc/` | Discovery, JWKS, JWT validation, the flow, in-memory state, and the two env-only settings |
| `crates/server/src/rest/oidc/` | The six `/api/auth/oidc/*` endpoints, plus `attach`, `guard_stray_callbacks` and `advertised_features` |
| `web/src/sso/` | The sign-in hook and components, the sign-out hook, the API client, and the `auth.sso*` translations |
| `docs/OIDC.md` | This file |

Upstream files hold only small hooks into those directories:

| Upstream file | Hook |
|---|---|
| `crates/server/src/rest/mod.rs` | `pub mod oidc;` and two `let app_logic = oidc::…(app_logic);` lines |
| `crates/server/src/rest/public/features.rs` | `features: crate::rest::oidc::advertised_features()` |
| `web/src/features/auth/user-auth-form.tsx` | `useSsoSignIn` plus three components |
| `web/src/components/sign-out-dialog.tsx` | `useSsoSignOut` |
| `README.md` | A pointer to this file |

`web/src/locales/*.json` are deliberately untouched: the SSO strings register
themselves from `web/src/sso/locales.ts`, with `overwrite: false` so an upstream
translation always wins if upstream ever adds one.

One further change in `web/src/main.tsx` is **not** part of this feature and is
worth keeping if the OIDC code is ever dropped: upstream reads `?access_token=`
from the URL and installs it as the session, which lets any crafted link plant one
and puts the token in browser history, `Referer`, and proxy logs. This fork
removes that reader; the handoff flow above replaces it.
