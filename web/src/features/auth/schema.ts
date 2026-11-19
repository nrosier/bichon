import type { TFunction } from 'i18next'
import { z } from 'zod'

export const getFormSchema = (t: TFunction) =>
  z.object({
    username: z
      .string()
      .min(1, { message: t('validation.pleaseEnterUsernameOrEmail') }),
    password: z
      .string()
      .min(1, { message: t('validation.pleaseEnterPassword') })
      .min(4, { message: t('validation.passwordMinLength', { min: 4 }) }),
    code: z.string().optional(),
  })

export type LoginFormValues = z.infer<ReturnType<typeof getFormSchema>>
