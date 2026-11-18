import { describe, expect, it } from 'vitest'
import en from '@/locales/en.json'
import ar from '@/locales/ar.json'
import cs from '@/locales/cs.json'
import da from '@/locales/da.json'
import de from '@/locales/de.json'
import es from '@/locales/es.json'
import fi from '@/locales/fi.json'
import fr from '@/locales/fr.json'
import itJson from '@/locales/it.json'
import jp from '@/locales/jp.json'
import ko from '@/locales/ko.json'
import nl from '@/locales/nl.json'
import no from '@/locales/no.json'
import pl from '@/locales/pl.json'
import pt from '@/locales/pt.json'
import ru from '@/locales/ru.json'
import sv from '@/locales/sv.json'
import zhTw from '@/locales/zh-tw.json'
import zh from '@/locales/zh.json'
import { SSO_ERROR_KEYS, ssoErrorKey } from '../locales'

const CODES = [
  'sso_unavailable',
  'sso_start_failed',
  'sso_failed',
  'sso_declined',
  'sso_incomplete',
  'sso_state_invalid',
  'sso_no_email',
  'sso_link_disabled',
  'sso_link_unverified_email',
  'email_domain_not_allowed',
  'discovery_invalid_issuer',
  'discovery_dns',
  'discovery_connection_refused',
  'discovery_timeout',
  'discovery_tls',
  'discovery_network',
  'discovery_redirect',
  'discovery_not_found',
  'discovery_access_denied',
  'discovery_server_error',
  'discovery_http_error',
  'discovery_not_json',
  'discovery_incomplete',
  'discovery_issuer_mismatch',
]

const LOCALES: Record<string, unknown> = {
  en, ar, cs, da, de, es, fi, fr, it: itJson, jp, ko, nl, no, pl, pt, ru, sv, 'zh-tw': zhTw, zh,
}

describe('ssoErrorKey', () => {
  it.each(CODES)('maps %s to a sso.error key', (code) => {
    expect(ssoErrorKey(code)).toBe(`sso.error.${code}`)
  })

  it('returns undefined for an unknown code', () => {
    expect(ssoErrorKey('not_a_code')).toBeUndefined()
  })

  it('does not treat inherited object properties as codes', () => {
    expect(ssoErrorKey('toString')).toBeUndefined()
    expect(ssoErrorKey('__proto__')).toBeUndefined()
  })

  it('covers exactly the listed codes', () => {
    expect(Object.keys(SSO_ERROR_KEYS).sort()).toEqual([...CODES].sort())
  })
})

describe('sso.error locale parity', () => {
  it.each(Object.keys(LOCALES))('%s contains every key the map returns', (name) => {
    const messages = (LOCALES[name] as { sso?: { error?: Record<string, unknown> } }).sso
      ?.error
    expect(messages).toBeDefined()
    for (const code of CODES) {
      const text = messages?.[code]
      expect(typeof text, `${name} is missing ${code}`).toBe('string')
      expect((text as string).length, `${name} has empty ${code}`).toBeGreaterThan(0)
    }
  })
})
