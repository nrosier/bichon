import { z } from 'zod'
import { requiredError } from '@/lib/zod-errors'

export const profileSchema = (t: (key: string) => string) =>
  z.object({
    username: z
      .string({
        error: requiredError(t('settings.profile.validation.username.required')),
      })
      .min(3, {
        message: t('settings.profile.validation.username.min'),
      })
      .max(32, {
        message: t('settings.profile.validation.username.max'),
      }),

    email: z
      .string({
        error: requiredError(t('settings.profile.validation.email.required')),
      })
      .email({
        message: t('settings.profile.validation.email.invalid'),
      }),

    password: z
      .string()
      .min(8, {
        message: t('settings.profile.validation.password.min'),
      })
      .max(256, {
        message: t('settings.profile.validation.password.max'),
      })
      .or(z.literal(''))
      .optional()
      .transform((v) => (v ? v : undefined)),
  })

export type ProfileFormValues = z.infer<ReturnType<typeof profileSchema>>
export type ProfileFormInput = z.input<ReturnType<typeof profileSchema>>
