import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'

const mocks = vi.hoisted(() => ({
  search: { oidc_error: 'sso_declined' } as Record<string, string>,
  navigate: vi.fn(),
  toast: vi.fn(),
  setToken: vi.fn(),
}))

vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => mocks.navigate,
  useLocation: () => ({ search: mocks.search }),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string, fallback?: string) => fallback ?? key }),
}))

vi.mock('@/context/theme-context', () => ({
  useTheme: () => ({ setTheme: () => {} }),
}))

vi.mock('@/stores/authStore', () => ({ setToken: mocks.setToken }))

vi.mock('@/hooks/use-toast', () => ({ toast: mocks.toast }))

vi.mock('@/i18n', () => ({ default: { changeLanguage: () => {} } }))

vi.mock('../use-sso-config', () => ({
  useSsoConfig: () => ({ ssoEnabled: true, autoRedirect: true, isLoading: false }),
}))

vi.mock('../api', () => ({
  oidc_login_url: () => 'https://idp.example/login',
  redeem_oidc_handoff: vi.fn(),
}))

import { useSsoSignIn } from '../use-sso-sign-in'

beforeEach(() => {
  mocks.search = { oidc_error: 'sso_declined' }
  mocks.navigate.mockClear()
  mocks.toast.mockClear()
  mocks.setToken.mockClear()
})

describe('useSsoSignIn with oidc_error in the URL', () => {
  it('does not toast the error itself', async () => {
    renderHook(() => useSsoSignIn('/'))
    await waitFor(() => expect(mocks.navigate).toHaveBeenCalled())
    expect(mocks.toast).not.toHaveBeenCalled()
  })

  it('strips the code from the URL and does not redirect to the provider', async () => {
    const { result } = renderHook(() => useSsoSignIn('/'))
    await waitFor(() => expect(mocks.navigate).toHaveBeenCalled())
    expect(mocks.navigate).toHaveBeenCalledWith(
      expect.objectContaining({ to: '/sign-in', replace: true })
    )
    expect(result.current.phase).toBe('form')
  })
})
