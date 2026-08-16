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

import axiosInstance from '@/api/axiosInstance'
import { LoginResult } from '@/api/users/api'

export interface OidcConfigInfo {
  /** SSO is switched on and configured well enough to attempt. */
  enabled: boolean
  /** Skip the password form and go straight to the identity provider. */
  auto_redirect: boolean
}

/** Same shape as a password login, plus where the user was headed. */
export interface OidcHandoffResult extends LoginResult {
  redirect_to?: string | null
}

/**
 * Absolute URL of a backend endpoint.
 *
 * The login and logout endpoints answer with a redirect to the identity
 * provider, which only the browser can follow — so those are full-page
 * navigations rather than XHR, and they need the same prefix axios applies.
 */
export const backend_url = (path: string): string =>
  `${axiosInstance.defaults.baseURL ?? ''}${path}`

export const oidc_config = async (): Promise<OidcConfigInfo> => {
  const response = await axiosInstance.get<OidcConfigInfo>(
    'api/auth/oidc/config'
  )
  return response.data
}

/**
 * Start the flow. `redirect` is an in-app path to return to; the server
 * rejects anything that is not a local path.
 */
export const oidc_login_url = (redirect?: string): string => {
  const url = backend_url('/api/auth/oidc/login')
  return redirect && redirect !== '/'
    ? `${url}?redirect=${encodeURIComponent(redirect)}`
    : url
}

/**
 * Exchange a one-shot handoff id for the access token.
 *
 * A POST, so the token only ever appears in a response body — never in the
 * URL, in `Referer`, or in a proxy access log.
 */
export const redeem_oidc_handoff = async (
  id: string
): Promise<OidcHandoffResult> => {
  const response = await axiosInstance.post<OidcHandoffResult>(
    'api/auth/oidc/handoff',
    { id }
  )
  return response.data
}

/**
 * Revoke this browser's access token server-side, leaving the identity
 * provider session alone.
 */
export const oidc_local_logout = async (): Promise<void> => {
  await axiosInstance.post('api/auth/oidc/local-logout')
}

/** RP-initiated logout: ends the identity provider session too. */
export const oidc_logout_url = (): string =>
  backend_url('/api/auth/oidc/logout')
