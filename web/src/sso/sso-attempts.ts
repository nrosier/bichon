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

export const recordSsoAttempt = () => {
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
export const ssoRedirectExhausted = (): boolean => {
  const attempts = readSsoAttempts()
  if (attempts === null) return false

  const now = Date.now()
  if (now - attempts.first >= SSO_WINDOW_MS) return false
  return now - attempts.last < SSO_BOUNCE_MS || attempts.count >= SSO_MAX_ATTEMPTS
}
