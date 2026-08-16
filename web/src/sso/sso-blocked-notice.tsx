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

import { useTranslation } from 'react-i18next'
import type { SsoSignIn as SsoSignInState } from './use-sso-sign-in'

interface SsoBlockedNoticeProps {
  sso: SsoSignInState
}

/**
 * Explains why the page stopped redirecting to the identity provider on its own.
 *
 * Renders nothing in the ordinary case, so the caller can drop it in above the
 * password form unconditionally.
 */
export function SsoBlockedNotice({ sso }: SsoBlockedNoticeProps) {
  const { t } = useTranslation()
  if (!sso.loopBlocked) return null

  return (
    <p className='border-destructive/50 bg-destructive/10 text-destructive rounded-md border p-3 text-sm'>
      {t(
        'auth.ssoLoopBlocked',
        'Single sign-on returned without a session, so Bichon stopped retrying. Sign in below, or ask an administrator to check the OIDC redirect URI.'
      )}
    </p>
  )
}
