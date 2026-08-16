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

import { HTMLAttributes } from 'react'
import { Loader2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/button'
import { cn } from '@/lib/utils'
import type { SsoSignIn as SsoSignInState } from './use-sso-sign-in'

interface SsoInterstitialProps extends HTMLAttributes<HTMLDivElement> {
  sso: SsoSignInState
}

/**
 * Shown in place of the password form while single sign-on has the floor —
 * either redeeming a handoff or about to leave for the provider.
 */
export function SsoInterstitial({
  sso,
  className,
  ...props
}: SsoInterstitialProps) {
  const { t } = useTranslation()
  const redeeming = sso.phase === 'redeeming'

  return (
    <div
      className={cn('grid justify-items-center gap-4 py-8', className)}
      {...props}
    >
      <div className='text-muted-foreground flex items-center gap-2 text-sm'>
        <Loader2 className='animate-spin' size={16} />
        {redeeming
          ? t('auth.ssoCompleting', 'Completing sign-in...')
          : t('auth.ssoRedirecting', 'Redirecting to your identity provider...')}
      </div>
      {/* The way out when the provider is unreachable or hangs. */}
      {!redeeming && (
        <Button variant='ghost' size='sm' type='button' onClick={sso.backToForm}>
          {t('auth.ssoUseLocal', 'Use a local account')}
        </Button>
      )}
    </div>
  )
}
