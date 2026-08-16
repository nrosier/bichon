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


import { useNavigate, useLocation } from '@tanstack/react-router'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { resetToken } from '@/stores/authStore'
import { useTranslation } from 'react-i18next'
import { useCurrentUser } from '@/hooks/use-current-user'
import { useOidc } from '@/hooks/use-oidc'
import { oidc_local_logout, oidc_logout_url } from '@/api/oidc/api'
import { useState } from 'react'

interface SignOutDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function SignOutDialog({ open, onOpenChange }: SignOutDialogProps) {
  const navigate = useNavigate()
  const location = useLocation()
  const { t } = useTranslation()
  const { user } = useCurrentUser()
  const { ssoEnabled } = useOidc()
  const [isLoading, setIsLoading] = useState(false)

  const isSsoUser =
    ssoEnabled && !!user?.sso_provider && user.sso_provider !== ''

  const goToSignIn = (currentPath: string) => {
    navigate({
      // `local=1` keeps the password form up instead of bouncing the user
      // straight back into the provider they just signed out of.
      to: '/sign-in',
      search: { local: '1', redirect: currentPath },
      replace: true,
    })
  }

  const localSignOut = () => {
    resetToken()
    goToSignIn(location.href)
  }

  const handleConfirm = () => {
    if (!isSsoUser) {
      localSignOut()
      return
    }
    setIsLoading(true)
    // Only sign out of Bichon; keep the SSO session for one-click sign-in.
    // This revokes the token server-side, so clearing local storage is no
    // longer all that stands between a copied token and the API.
    oidc_local_logout()
      .catch(() => {})
      .finally(() => {
        setIsLoading(false)
        localSignOut()
      })
  }

  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('sign_out.title', 'Sign out')}
      desc={
        isSsoUser
          ? t(
              'sign_out.sso_desc',
              'Signing out of Bichon only keeps your SSO session (e.g. Keycloak) active. For full security, choose "Sign out and end SSO session".'
            )
          : t(
              'sign_out.desc',
              'Are you sure you want to sign out? You will need to sign in again to access your account.'
            )
      }
      confirmText={
        isSsoUser
          ? t('sign_out.confirm_sso', 'Sign out of Bichon only')
          : t('sign_out.confirm', 'Sign out')
      }
      destructive
      isLoading={isLoading}
      handleConfirm={handleConfirm}
      className="sm:max-w-sm"
    >
      {isSsoUser && (
        <div className='grid gap-2'>
          <button
            type='button'
            className='inline-flex h-10 items-center justify-center gap-2 rounded-md border border-destructive/50 bg-background px-4 text-sm font-medium text-destructive transition-colors hover:bg-destructive/10'
            disabled={isLoading}
            onClick={() => {
              setIsLoading(true)
              // Revoke here, because the navigation that follows cannot carry
              // the Authorization header the server would need to do it.
              oidc_local_logout()
                .catch(() => {})
                .finally(() => {
                  resetToken()
                  window.location.href = oidc_logout_url()
                })
            }}
          >
            {t('sign_out.full_sign_out', 'Sign out and end SSO session')}
          </button>
          <p className='text-muted-foreground px-2 text-xs'>
            {t(
              'sign_out.sso_warning',
              'This will end your SSO session (e.g. Keycloak) and sign you out of all applications using it.'
            )}
          </p>
        </div>
      )}
    </ConfirmDialog>
  )
}
