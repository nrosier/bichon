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
| `BICHON_OIDC_LINK_BY_EMAIL` | `false` | Allow a provider-asserted email address to adopt the existing Bichon account with that address. See [User resolution](#behaviour) |
| `BICHON_OIDC_ALLOW_INSECURE_ISSUER` | `false` | Accept a non-loopback `http://` issuer. See [Transport](#transport) |

The first five are fields of Bichon's own `Settings` struct, so they also accept
CLI flags (`--bichon-oidc-issuer-url`) and appear in the settings API.

The last four are **environment-only** — no `--flag` form, and not in the settings
API. They are this fork's own settings, and keeping them out of upstream's
`Settings` struct is what lets `crates/core/src/settings/` stay byte-identical to
upstream. They are read in
[`crates/core/src/oidc/config.rs`](../crates/core/src/oidc/config.rs) instead. A
typo in any of them is a startup error rather than a silent default, so
`BICHON_OIDC_AUTO_REDIRECT=yes` will not quietly leave auto-redirect off, and
`BICHON_OIDC_LINK_BY_EMAIL=yes` will not read as enabled while being off.

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
`(sso_provider, sso_id)` first. If that finds nobody, and no Bichon account has the
asserted email address, a new user is auto-provisioned with
`BICHON_OIDC_DEFAULT_ROLE_ID`. The `sub` claim from the IdP is stored on the user
and used for subsequent logins, so this lookup is all that runs from then on.

An account that *does* already have that address is only adopted when **both**
conditions hold; otherwise the login is refused, with the reason in the server log:

- `BICHON_OIDC_LINK_BY_EMAIL=true`, and
- the provider asserts `email_verified: true` for the address (in the ID token, or
  in the userinfo response when the email came from there).

Linking hands over that account's roles, ACLs and mailbox access on the strength of
an email address. Wherever a principal can self-register at the provider, or edit
their own profile email without confirming it, that would let someone claim an
address they do not own and inherit the Bichon account behind it — so it has to be
asked for, and the provider has to be willing to vouch for the address.

Refusing rather than provisioning a second account is deliberate: a duplicate
address is confusing on its own, and it would bury the fact that a real account was
nearly handed out.

Linking is the only way an existing account picks up an SSO identity — a password
login never attaches one. So to move existing local users onto SSO, turn
`BICHON_OIDC_LINK_BY_EMAIL` on for the migration (with the addresses verified at
the provider) and off again afterwards; every user who has signed in once by then
matches on `(sso_provider, sso_id)` and is unaffected by the setting from that point
on. Users you would rather give a fresh account can have their old account's
address changed instead.

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

**Provider-reported errors.** When the provider declines a sign-in it redirects to
the callback with `error` and `error_description`. Both are written to the server
log; the browser gets a fixed message pointing at that log. The callback is a public
endpoint that needs no valid `state`, so anyone can put arbitrary text in
`error_description` — echoing it would render an attacker's words in Bichon's own UI,
on Bichon's own origin.

## Transport

`BICHON_OIDC_ISSUER_URL` must be `https`. Everything Bichon exchanges over it is a
bearer secret — the client secret on the token request, the authorization code, and
the ID token coming back — and anything on the network path of a plain-HTTP issuer
can read all three, or answer for the issuer and mint an ID token for any user.

Two exceptions:

- **Loopback** (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`) is accepted as
  `http` without any setting: there is no network to be on the path of, and that is
  how the flow is usually developed against.
- **Anything else** on `http` needs `BICHON_OIDC_ALLOW_INSECURE_ISSUER=true`. It
  exists so a working LAN deployment is not broken by an upgrade, and it logs a
  warning once per process saying what is exposed.

Non-`http(s)` schemes are rejected either way. A bad value fails
`OidcConfig::load()`, which means SSO reports itself unavailable rather than the
server failing to start — local login keeps working while the URL is corrected.

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
