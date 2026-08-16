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

/**
 * OIDC single sign-on for the WebUI.
 *
 * Upstream Bichon ships SSO only in its paid edition, so nothing in this
 * directory will ever arrive from a resync. It is arranged to keep that resync
 * cheap: the whole feature is imported through this one module, and the upstream
 * files that use it — `features/auth/user-auth-form.tsx` and
 * `components/sign-out-dialog.tsx` — keep diffs small enough to re-apply by hand
 * if they ever conflict.
 */

// Imported for its side effect: registers the `auth.sso*` strings, so
// `src/locales/*.json` stay exactly as upstream wrote them.
import './locales'

export { SsoBlockedNotice } from './sso-blocked-notice'
export { SsoInterstitial } from './sso-interstitial'
export { SsoSignIn } from './sso-sign-in'
export { useSsoSignIn, type SsoPhase } from './use-sso-sign-in'
export { useSsoSignOut } from './use-sso-sign-out'
