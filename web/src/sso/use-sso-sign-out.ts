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

import { resetToken } from '@/stores/authStore'
import { useCurrentUser } from '@/hooks/use-current-user'
import { oidc_local_logout, oidc_logout_url } from './api'
import { useSsoConfig } from './use-sso-config'

export interface SsoSignOut {
  /** This session came from the identity provider, so both exits are offered. */
  isSsoUser: boolean
  /**
   * Sign out of Bichon and keep the provider session, for one-click sign-in.
   * Resolves once the token is revoked; it never rejects.
   */
  localSignOut: () => Promise<void>
  /** RP-initiated logout: ends the provider session too, and navigates away. */
  fullSignOut: () => Promise<void>
}

/**
 * The two ways out of an SSO session.
 *
 * Both revoke the access token server-side first, so clearing local storage is
 * no longer all that stands between a copied token and the API.
 */
export function useSsoSignOut(): SsoSignOut {
  const { user } = useCurrentUser()
  const { ssoEnabled } = useSsoConfig()

  return {
    isSsoUser: ssoEnabled && !!user?.sso_provider && user.sso_provider !== '',

    localSignOut: () => oidc_local_logout().catch(() => {}),

    fullSignOut: () =>
      // Revoke before navigating, because a full-page navigation cannot carry
      // the Authorization header the server would need to do it.
      oidc_local_logout()
        .catch(() => {})
        .finally(() => {
          resetToken()
          window.location.href = oidc_logout_url()
        }),
  }
}
