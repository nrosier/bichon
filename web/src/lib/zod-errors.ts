import type { core } from 'zod'

// zod 4 replaced the `required_error` / `invalid_type_error` options with a single
// `error` option. These helpers keep the zod 3 split: a missing (undefined) value
// gets the "required" message, any other wrong-typed value gets the "invalid type"
// message, and every other issue keeps zod's default message.
type TypeIssue = core.$ZodRawIssue

export const requiredError = (message: string) => (iss: TypeIssue) =>
  iss.input === undefined ? message : undefined

export const invalidTypeError = (message: string) => (iss: TypeIssue) =>
  iss.input === undefined ? undefined : message
