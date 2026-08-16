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

import { Shield } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/button'
import type { SsoSignIn as SsoSignInState } from './use-sso-sign-in'

interface SsoSignInProps {
  sso: SsoSignInState
  /** True while a password login is in flight, so both buttons settle together. */
  disabled?: boolean
}

/**
 * The "or sign in with SSO" half of the sign-in page.
 *
 * Renders nothing when the server has no identity provider configured, which is
 * what lets the caller drop it in unconditionally.
 */
export function SsoSignIn({ sso, disabled }: SsoSignInProps) {
  const { t } = useTranslation()
  if (!sso.enabled) return null

  return (
    // Both ways in stay on the page, so the account someone has is the one they
    // can use — a local password or the identity provider.
    <div className='mt-4 grid gap-4'>
      <div className='flex items-center gap-3'>
        <span className='bg-border h-px flex-1' />
        <span className='text-muted-foreground text-xs uppercase'>
          {t('auth.ssoOr', 'or')}
        </span>
        <span className='bg-border h-px flex-1' />
      </div>
      <Button
        variant='outline'
        type='button'
        disabled={disabled}
        onClick={sso.startSso}
      >
        <Shield size={16} className='mr-2' />
        {t('auth.ssoLogin')}
      </Button>
    </div>
  )
}
