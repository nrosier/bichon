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

import { useEffect, useRef, useState } from 'react'
import { AxiosError } from 'axios'
import { useLocation, useNavigate } from '@tanstack/react-router'
import { useTranslation } from 'react-i18next'
import { setToken } from '@/stores/authStore'
import { toSearchParams } from '@/lib/utils'
import { toast } from '@/hooks/use-toast'
import { ToastAction } from '@/components/ui/toast'
import { useTheme } from '@/context/theme-context'
import i18n from '@/i18n'
import {
  oidc_login_url,
  redeem_oidc_handoff,
  type OidcHandoffResult,
} from './api'
import { useSsoConfig } from './use-sso-config'
import { recordSsoAttempt, ssoRedirectExhausted } from './sso-attempts'

/** What the sign-in page should show while SSO has the floor. */
export type SsoPhase =
  /** Nothing SSO-related in flight; show the password form. */
  | 'form'
  /** Trading a handoff id for the access token. */
  | 'redeeming'
  /** About to hand the browser to the identity provider. */
  | 'leaving'

export interface SsoSignIn {
  /** SSO is configured on this server, so the button belongs on the page. */
  enabled: boolean
  phase: SsoPhase
  /** Auto-redirect was stopped because the round trip kept coming back empty. */
  loopBlocked: boolean
  /** Hand the browser to the identity provider. */
  startSso: () => void
  /** Back to a clean sign-in page, with the password form showing. */
  backToForm: () => void
}

/**
 * Everything the sign-in page does about single sign-on.
 *
 * All of it lives here rather than in `UserAuthForm` so that upstream file keeps
 * a four-line diff: SSO is a paid feature upstream, so none of this will ever
 * arrive from a resync, and a resync should not have to merge it back together.
 *
 * `redirect` is where the user was headed, which the caller already has.
 */
export function useSsoSignIn(redirect: string): SsoSignIn {
  const navigate = useNavigate()
  const { setTheme } = useTheme()
  const { t } = useTranslation()
  const { search } = useLocation()
  const params = toSearchParams(search)

  // Set by the OIDC callback: a one-shot id to trade for the access token, or a
  // message explaining why the sign-in did not happen.
  const handoffId = params.get('oidc_handoff')
  const oidcError = params.get('oidc_error')
  // `?local=1` is the escape hatch that reaches the password form even when the
  // server is configured to redirect straight to the provider.
  const localOnly = params.get('local') === '1'

  const { ssoEnabled, autoRedirect, isLoading: oidcLoading } = useSsoConfig()
  const [isRedeeming, setIsRedeeming] = useState(!!handoffId)

  // Decided once, from the state the page was loaded with: we are back on the
  // sign-in page after leaving for the provider, with neither a handoff nor an
  // explanation. Something in the round trip is misconfigured, and starting it
  // again would only spin.
  const [loopBlocked] = useState(
    () => !handoffId && !oidcError && ssoRedirectExhausted()
  )

  /**
   * Store the session and continue to wherever the user was headed.
   *
   * Deliberately a copy of what upstream's `onSubmit` does inline, rather than a
   * helper both call: extracting it would mean editing their function.
   */
  const applyLogin = (result: OidcHandoffResult, target: string) => {
    setToken(result)

    if (result.theme) {
      setTheme(result.theme)
    }

    if (result.language) {
      i18n.changeLanguage(result.language)
    }

    navigate({ to: target })
  }

  const backToForm = () => {
    // `local=1` matters when the server auto-redirects: without it we would
    // bounce straight back to the provider that just turned us away.
    navigate({
      to: '/sign-in',
      search: redirect !== '/' ? { local: '1', redirect } : { local: '1' },
      replace: true,
    })
  }

  const startSso = () => {
    recordSsoAttempt()
    window.location.href = oidc_login_url(redirect)
  }

  // Each of these runs once. StrictMode double-invokes effects in development,
  // and a handoff id only works the first time it is redeemed.
  const notifiedError = useRef(false)
  const redeemed = useRef(false)
  const startedRedirect = useRef(false)

  useEffect(() => {
    if (!oidcError || notifiedError.current) return
    notifiedError.current = true

    toast({
      variant: 'destructive',
      title: t('auth.ssoFailed', 'Single sign-on failed'),
      description: oidcError,
      action: (
        <ToastAction altText={t('common.tryAgain')}>
          {t('common.tryAgain')}
        </ToastAction>
      ),
    })
    // Drop the message from the URL so a refresh does not replay it.
    backToForm()
  }, [oidcError])

  useEffect(() => {
    if (!handoffId || redeemed.current) return
    redeemed.current = true

    redeem_oidc_handoff(handoffId)
      .then((result) => {
        if (!result.success || !result.access_token) {
          throw new Error(
            result.error_message ??
              t('auth.ssoHandoffFailed', 'The sign-in could not be completed.')
          )
        }
        applyLogin(result, result.redirect_to || redirect)
      })
      .catch((error) => {
        setIsRedeeming(false)
        // A rejected handoff answers 401 with its own explanation; prefer that
        // over axios's "Request failed with status code 401".
        const fromServer =
          error instanceof AxiosError
            ? (error.response?.data as OidcHandoffResult | undefined)
                ?.error_message
            : null
        toast({
          variant: 'destructive',
          title: t('auth.ssoFailed', 'Single sign-on failed'),
          description:
            fromServer ||
            t('auth.ssoHandoffFailed', 'The sign-in could not be completed.'),
          action: (
            <ToastAction altText={t('common.tryAgain')}>
              {t('common.tryAgain')}
            </ToastAction>
          ),
        })
        backToForm()
      })
  }, [handoffId])

  useEffect(() => {
    if (oidcLoading || !ssoEnabled || !autoRedirect) return
    if (localOnly || handoffId || oidcError || startedRedirect.current) return
    if (loopBlocked) return
    startedRedirect.current = true
    startSso()
  }, [
    oidcLoading,
    ssoEnabled,
    autoRedirect,
    localOnly,
    handoffId,
    oidcError,
    loopBlocked,
  ])

  // Either we are mid-handoff or about to leave for the provider. Showing the
  // password form in that gap would only invite the user to type into it.
  const leavingForProvider =
    !oidcLoading &&
    ssoEnabled &&
    autoRedirect &&
    !localOnly &&
    !oidcError &&
    !loopBlocked

  return {
    enabled: ssoEnabled,
    phase: isRedeeming ? 'redeeming' : leavingForProvider ? 'leaving' : 'form',
    loopBlocked,
    startSso,
    backToForm,
  }
}
