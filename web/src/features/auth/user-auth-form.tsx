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


import { HTMLAttributes, useEffect, useRef, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { cn, toSearchParams } from '@/lib/utils'
import { getFormSchema, type LoginFormValues } from './schema'
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { PasswordInput } from '@/components/password-input'
import { useMutation } from '@tanstack/react-query'
import { setToken } from '@/stores/authStore'
import { toast } from '@/hooks/use-toast'
import { AxiosError } from 'axios'
import { ToastAction } from '@/components/ui/toast'
import { useLocation, useNavigate } from '@tanstack/react-router'
import { Button } from '@/components/button'
import { useTranslation } from 'react-i18next'
import i18n from '@/i18n'
import { Loader2, LogIn, Shield } from 'lucide-react'
import { login, type LoginResult } from '@/api/users/api'
import { useTheme } from '@/context/theme-context'
import { useOidc } from '@/hooks/use-oidc'
import {
  oidc_login_url,
  redeem_oidc_handoff,
  type OidcHandoffResult,
} from '@/api/oidc/api'

type UserAuthFormProps = HTMLAttributes<HTMLDivElement>

/** Recent hand-offs to the identity provider, kept per tab. */
const SSO_ATTEMPT_KEY = 'bichon.oidc.attempts'
/** A round trip that returns inside this window without a session is a bounce. */
const SSO_BOUNCE_MS = 30_000
/** Attempts older than this stop counting, so an idle tab is never held back. */
const SSO_WINDOW_MS = 120_000
/** Hand-offs per window before Bichon stops starting them by itself. */
const SSO_MAX_ATTEMPTS = 3

interface SsoAttempts {
  count: number
  /** When the current window opened. */
  first: number
  /** When we last left for the provider. */
  last: number
}

const readSsoAttempts = (): SsoAttempts | null => {
  try {
    const raw = sessionStorage.getItem(SSO_ATTEMPT_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as SsoAttempts
    return [parsed?.count, parsed?.first, parsed?.last].every(Number.isFinite)
      ? parsed
      : null
  } catch {
    // Unparseable, or storage refused: the guard simply does not apply.
    return null
  }
}

const recordSsoAttempt = () => {
  const now = Date.now()
  const previous = readSsoAttempts()
  const inWindow = previous !== null && now - previous.first < SSO_WINDOW_MS
  const attempts: SsoAttempts = {
    count: inWindow ? previous.count + 1 : 1,
    first: inWindow ? previous.first : now,
    last: now,
  }
  try {
    sessionStorage.setItem(SSO_ATTEMPT_KEY, JSON.stringify(attempts))
  } catch {
    // Private-mode storage refusals only cost us the loop guard.
  }
}

/**
 * Whether to stop handing the browser to the provider on our own.
 *
 * Two ways a sign-in that never takes hold would otherwise repeat forever: it
 * comes straight back (the provider already has a session, so each lap costs
 * under a second), or it comes back slowly but just as fruitlessly. Nothing here
 * limits a button press — only what the page does unprompted.
 */
const ssoRedirectExhausted = (): boolean => {
  const attempts = readSsoAttempts()
  if (attempts === null) return false

  const now = Date.now()
  if (now - attempts.first >= SSO_WINDOW_MS) return false
  return now - attempts.last < SSO_BOUNCE_MS || attempts.count >= SSO_MAX_ATTEMPTS
}

export function UserAuthForm({ className, ...props }: UserAuthFormProps) {
  const [isLoading, setIsLoading] = useState(false)
  const { setTheme } = useTheme();
  const navigate = useNavigate()
  const { t } = useTranslation()
  const { search } = useLocation();
  const params = toSearchParams(search)
  const redirect = params.get('redirect') || '/';

  // Set by the OIDC callback: a one-shot id to trade for the access token, or a
  // message explaining why the sign-in did not happen.
  const handoffId = params.get('oidc_handoff')
  const oidcError = params.get('oidc_error')
  // `?local=1` is the escape hatch that reaches the password form even when the
  // server is configured to redirect straight to the provider.
  const localOnly = params.get('local') === '1'

  const { ssoEnabled, autoRedirect, isLoading: oidcLoading } = useOidc()
  const [isRedeeming, setIsRedeeming] = useState(!!handoffId)

  // Decided once, from the state the page was loaded with: we are back on the
  // sign-in page after leaving for the provider, with neither a handoff nor an
  // explanation. Something in the round trip is misconfigured, and starting it
  // again would only spin.
  const [loopBlocked] = useState(
    () => !handoffId && !oidcError && ssoRedirectExhausted()
  )

  const formSchema = getFormSchema(t)
  const form = useForm<LoginFormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      username: '',
      password: '',
    },
  })

  const mutation = useMutation({
    mutationFn: (data: Record<string, any>) => login(data),
    retry: 0,
  });

  /** Store the session and continue to wherever the user was headed. */
  const applyLogin = (result: LoginResult, target: string) => {
    setToken(result)

    if (result.theme) {
      setTheme(result.theme)
    }

    if (result.language) {
      i18n.changeLanguage(result.language)
    }

    navigate({ to: target })
  }

  /** Back to a clean sign-in page, with the password form showing. */
  const backToForm = () => {
    // `local=1` matters when the server auto-redirects: without it we would
    // bounce straight back to the provider that just turned us away.
    navigate({
      to: '/sign-in',
      search: redirect !== '/' ? { local: '1', redirect } : { local: '1' },
      replace: true,
    })
  }

  /** Hand the browser to the identity provider. */
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
      action: <ToastAction altText={t('common.tryAgain')}>{t('common.tryAgain')}</ToastAction>,
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
          action: <ToastAction altText={t('common.tryAgain')}>{t('common.tryAgain')}</ToastAction>,
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
  }, [oidcLoading, ssoEnabled, autoRedirect, localOnly, handoffId, oidcError, loopBlocked])

  async function onSubmit(data: LoginFormValues) {
    setIsLoading(true)

    mutation.mutate(data, {
      onSuccess: (result) => {
        if (result.success) {
          applyLogin(result, redirect);
        } else {
          toast({
            variant: "destructive",
            title: t('auth.loginFailed'),
            description: `${result.error_message!}`,
            action: <ToastAction altText={t('common.tryAgain')}>{t('common.tryAgain')}</ToastAction>,
          })
        }
        setIsLoading(false);
      },
      onError: (error) => {
        const { t } = i18n
        if (error instanceof AxiosError && error.response && error.response.status === 401) {
          toast({
            variant: "destructive",
            title: t('auth.loginFailed'),
            description: t('auth.invalidPassword'),
            action: <ToastAction altText={t('common.tryAgain')}>{t('common.tryAgain')}</ToastAction>,
          })
        } else {
          toast({
            variant: "destructive",
            title: t('auth.somethingWentWrong'),
            description: (error as Error).message,
            action: <ToastAction altText={t('common.tryAgain')}>{t('common.tryAgain')}</ToastAction>,
          })
        }
        setIsLoading(false)
      }
    });
  }

  // Either we are mid-handoff or about to leave for the provider. Showing the
  // password form in that gap would only invite the user to type into it.
  const leavingForProvider =
    !oidcLoading && ssoEnabled && autoRedirect && !localOnly && !oidcError && !loopBlocked
  if (isRedeeming || leavingForProvider) {
    return (
      <div className={cn('grid justify-items-center gap-4 py-8', className)} {...props}>
        <div className='text-muted-foreground flex items-center gap-2 text-sm'>
          <Loader2 className='animate-spin' size={16} />
          {isRedeeming
            ? t('auth.ssoCompleting', 'Completing sign-in...')
            : t('auth.ssoRedirecting', 'Redirecting to your identity provider...')}
        </div>
        {/* The way out when the provider is unreachable or hangs. */}
        {!isRedeeming && (
          <Button variant='ghost' size='sm' type='button' onClick={backToForm}>
            {t('auth.ssoUseLocal', 'Use a local account')}
          </Button>
        )}
      </div>
    )
  }

  return (
    <div className={cn('grid gap-6', className)} {...props}>
      {loopBlocked && (
        <p className='border-destructive/50 bg-destructive/10 text-destructive rounded-md border p-3 text-sm'>
          {t(
            'auth.ssoLoopBlocked',
            'Single sign-on returned without a session, so Bichon stopped retrying. Sign in below, or ask an administrator to check the OIDC redirect URI.'
          )}
        </p>
      )}
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)}>
          <div className='grid gap-2'>
            <FormField
              control={form.control}
              name='username'
              render={({ field }) => (
                <FormItem className='space-y-1'>
                  <FormLabel>{t('auth.username')}</FormLabel>
                  <FormControl>
                    <Input {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name='password'
              render={({ field }) => (
                <FormItem className='space-y-1'>
                  <div className='flex items-center justify-between'>
                    <FormLabel>{t('auth.password')}</FormLabel>
                  </div>
                  <FormControl>
                    <PasswordInput placeholder='********' {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button className='mt-2' disabled={isLoading}>
              {isLoading ? <Loader2 className='animate-spin' /> : <LogIn size={16} className='mr-2' />}
              {t('auth.login')}
            </Button>
          </div>
        </form>
      </Form>

      {/* Both ways in stay on the page, so the account someone has is the one
          they can use — a local password or the identity provider. */}
      {ssoEnabled && (
        <div className='grid gap-4'>
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
            disabled={isLoading}
            onClick={startSso}
          >
            <Shield size={16} className='mr-2' />
            {t('auth.ssoLogin')}
          </Button>
        </div>
      )}
    </div>
  )
}