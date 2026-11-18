import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@/test/test-utils'
import i18n from '@/i18n'
import { UserAuthForm } from '../user-auth-form'

// The error code arrives as ?oidc_error=<code>; the sign-in hook strips it from
// the URL, so the form must still show the message. The SSO button follows
// `isPro || ssoSupported`.

const mocks = vi.hoisted(() => ({
  search: {} as Record<string, string>,
  navigate: vi.fn(),
  toast: vi.fn(),
  edition: { isPro: false, ssoSupported: true, ssoEnabled: true, ldapEnabled: false },
}))

vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => mocks.navigate,
  useLocation: () => ({ search: mocks.search }),
}))

vi.mock('@/hooks/use-edition', () => ({
  useEdition: () => mocks.edition,
}))

vi.mock('@/hooks/use-toast', () => ({ toast: mocks.toast }))

vi.mock('@/context/theme-context', () => ({
  useTheme: () => ({ setTheme: () => {} }),
}))

vi.mock('@/api/users/api', () => ({
  login: vi.fn(),
  ldapLogin: vi.fn(),
  mfaVerify: vi.fn(),
}))

vi.mock('@/api/sso/api', () => ({
  get_sso_status: vi.fn(async () => ({
    configured: true,
    available: true,
    code: null,
    checked_at: 1,
  })),
}))

vi.mock('@/sso/use-sso-config', () => ({
  useSsoConfig: () => ({ ssoEnabled: true, autoRedirect: false, isLoading: false }),
}))

beforeEach(() => {
  mocks.search = {}
  mocks.navigate.mockClear()
  mocks.toast.mockClear()
  mocks.edition = { isPro: false, ssoSupported: true, ssoEnabled: true, ldapEnabled: false }
})

describe('sign-in page oidc_error', () => {
  it('shows the translated message for a known code, after the hook strips it', async () => {
    mocks.search = { oidc_error: 'sso_declined' }
    render(<UserAuthForm />)

    await waitFor(() => expect(mocks.toast).toHaveBeenCalledTimes(1))
    expect(mocks.toast).toHaveBeenCalledWith(
      expect.objectContaining({
        description: i18n.t('sso.error.sso_declined', { status: '-' }),
      })
    )
    expect(i18n.t('sso.error.sso_declined')).not.toBe('sso.error.sso_declined')
    // The hook did strip the code from the URL.
    expect(mocks.navigate).toHaveBeenCalledWith(
      expect.objectContaining({ to: '/sign-in', replace: true })
    )
  })

  it('names an unknown code instead of mapping it', async () => {
    mocks.search = { oidc_error: 'not_a_real_code' }
    render(<UserAuthForm />)

    await waitFor(() =>
      expect(mocks.toast).toHaveBeenCalledWith(
        expect.objectContaining({
          description: 'The identity provider returned: not_a_real_code',
        })
      )
    )
  })
})

describe('sign-in page SSO button', () => {
  it('shows when SSO is supported on a non-Pro server', async () => {
    render(<UserAuthForm />)

    expect(await screen.findByText(i18n.t('auth.ssoLogin'))).toBeInTheDocument()
  })

  it('is hidden when the server is neither Pro nor SSO-capable', () => {
    mocks.edition = { isPro: false, ssoSupported: false, ssoEnabled: false, ldapEnabled: false }
    render(<UserAuthForm />)

    expect(screen.queryByText(i18n.t('auth.ssoLogin'))).not.toBeInTheDocument()
  })
})
