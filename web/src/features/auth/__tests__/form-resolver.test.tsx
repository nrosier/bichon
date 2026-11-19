import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@/test/test-utils'
import i18n from '@/i18n'
import { login } from '@/api/users/api'
import { UserAuthForm } from '../user-auth-form'

// The zod resolver must turn schema failures into field messages. A resolver
// that does not understand the installed zod major re-throws the ZodError
// instead, and the form then shows nothing.

vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => () => {},
  useLocation: () => ({ search: {} }),
}))

vi.mock('@/hooks/use-edition', () => ({
  useEdition: () => ({ isPro: false, ssoEnabled: false, ldapEnabled: false }),
}))

vi.mock('@/context/theme-context', () => ({
  useTheme: () => ({ setTheme: () => {} }),
}))

vi.mock('@/api/users/api', () => ({
  login: vi.fn(),
  ldapLogin: vi.fn(),
  mfaVerify: vi.fn(),
}))

describe('sign-in form validation through zodResolver', () => {
  it('shows the field messages and does not submit when the fields are empty', async () => {
    const { container } = render(<UserAuthForm />)

    fireEvent.submit(container.querySelector('form')!)

    expect(
      await screen.findByText(i18n.t('validation.pleaseEnterUsernameOrEmail'))
    ).toBeInTheDocument()
    expect(screen.getByText(i18n.t('validation.pleaseEnterPassword'))).toBeInTheDocument()
    expect(login).not.toHaveBeenCalled()
  })
})
