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

/**
 * Translations for the SSO strings, kept out of `src/locales/*.json`.
 *
 * Those 18 files are upstream's, and upstream edits them often — adding eight
 * keys to each would make every resync a conflict in all eighteen. Registering
 * them from here instead leaves them untouched.
 *
 * Language keys and the `translation` namespace match what `@/i18n` sets up.
 * `en.ssoLogin` is upstream's own string (their paid edition has an SSO button
 * too) and is deliberately absent below — see the merge note on the register
 * call at the end of this file.
 */

import i18n from '@/i18n'

type SsoStrings = Record<string, string>

const SSO_TRANSLATIONS: Record<string, SsoStrings> = {
  en: {
    ssoCompleting: 'Completing sign-in...',
    ssoFailed: 'Single sign-on failed',
    ssoHandoffFailed: 'The sign-in could not be completed.',
    ssoLogin: 'Sign in with SSO',
    ssoLoopBlocked:
      'Single sign-on returned without a session, so Bichon stopped retrying. Sign in below, or ask an administrator to check the OIDC redirect URI.',
    ssoOr: 'or',
    ssoRedirecting: 'Redirecting to your identity provider...',
    ssoUseLocal: 'Use a local account',
  },
  ar: {
    ssoCompleting: 'جارٍ إكمال تسجيل الدخول...',
    ssoFailed: 'فشل الدخول الموحّد',
    ssoHandoffFailed: 'لم يتم إكمال تسجيل الدخول.',
    ssoLogin: 'تسجيل الدخول عبر SSO',
    ssoLoopBlocked:
      'عاد الدخول الموحّد دون إنشاء جلسة، لذلك أوقف Bichon إعادة المحاولة. سجّل الدخول أدناه أو اطلب من المسؤول التحقق من عنوان إعادة توجيه OIDC.',
    ssoOr: 'أو',
    ssoRedirecting: 'جارٍ إعادة التوجيه إلى مزوّد الهوية...',
    ssoUseLocal: 'استخدام حساب محلي',
  },
  da: {
    ssoCompleting: 'Fuldfører login...',
    ssoFailed: 'Single sign-on mislykkedes',
    ssoHandoffFailed: 'Login kunne ikke fuldføres.',
    ssoLogin: 'Log ind med SSO',
    ssoLoopBlocked:
      "Single sign-on vendte tilbage uden en session, så Bichon stoppede med at prøve igen. Log ind nedenfor, eller bed en administrator om at kontrollere OIDC-redirect-URI'en.",
    ssoOr: 'eller',
    ssoRedirecting: 'Omdirigerer til din identitetsudbyder...',
    ssoUseLocal: 'Brug en lokal konto',
  },
  de: {
    ssoCompleting: 'Anmeldung wird abgeschlossen...',
    ssoFailed: 'Single Sign-on fehlgeschlagen',
    ssoHandoffFailed: 'Die Anmeldung konnte nicht abgeschlossen werden.',
    ssoLogin: 'Mit SSO anmelden',
    ssoLoopBlocked:
      'Single Sign-on kehrte ohne Sitzung zurück, daher versucht Bichon es nicht erneut. Melden Sie sich unten an oder bitten Sie die Administration, die OIDC-Redirect-URI zu prüfen.',
    ssoOr: 'oder',
    ssoRedirecting: 'Weiterleitung zu Ihrem Identitätsanbieter...',
    ssoUseLocal: 'Lokales Konto verwenden',
  },
  es: {
    ssoCompleting: 'Completando el inicio de sesión...',
    ssoFailed: 'Error de inicio de sesión único',
    ssoHandoffFailed: 'No se pudo completar el inicio de sesión.',
    ssoLogin: 'Iniciar sesión con SSO',
    ssoLoopBlocked:
      'El inicio de sesión único regresó sin sesión, por lo que Bichon dejó de reintentar. Inicie sesión abajo o pida a un administrador que revise la URI de redirección de OIDC.',
    ssoOr: 'o',
    ssoRedirecting: 'Redirigiendo a su proveedor de identidad...',
    ssoUseLocal: 'Usar una cuenta local',
  },
  fi: {
    ssoCompleting: 'Viimeistellään kirjautumista...',
    ssoFailed: 'Kertakirjautuminen epäonnistui',
    ssoHandoffFailed: 'Kirjautumista ei voitu viimeistellä.',
    ssoLogin: 'Kirjaudu SSO:lla',
    ssoLoopBlocked:
      'Kertakirjautuminen palasi ilman istuntoa, joten Bichon lopetti yrittämisen. Kirjaudu alla tai pyydä ylläpitäjää tarkistamaan OIDC-uudelleenohjausosoite.',
    ssoOr: 'tai',
    ssoRedirecting: 'Ohjataan tunnistautumispalveluun...',
    ssoUseLocal: 'Käytä paikallista tiliä',
  },
  fr: {
    ssoCompleting: 'Finalisation de la connexion...',
    ssoFailed: "Échec de l'authentification unique",
    ssoHandoffFailed: "La connexion n'a pas pu être finalisée.",
    ssoLogin: 'Se connecter avec SSO',
    ssoLoopBlocked:
      "L'authentification unique est revenue sans session, Bichon a donc arrêté de réessayer. Connectez-vous ci-dessous ou demandez à un administrateur de vérifier l'URI de redirection OIDC.",
    ssoOr: 'ou',
    ssoRedirecting: "Redirection vers votre fournisseur d'identité...",
    ssoUseLocal: 'Utiliser un compte local',
  },
  it: {
    ssoCompleting: "Completamento dell'accesso...",
    ssoFailed: 'Accesso SSO non riuscito',
    ssoHandoffFailed: "Non è stato possibile completare l'accesso.",
    ssoLogin: 'Accedi con SSO',
    ssoLoopBlocked:
      "L'accesso SSO è tornato senza una sessione, quindi Bichon ha smesso di riprovare. Accedi qui sotto o chiedi a un amministratore di verificare l'URI di reindirizzamento OIDC.",
    ssoOr: 'oppure',
    ssoRedirecting: 'Reindirizzamento al tuo provider di identità...',
    ssoUseLocal: 'Usa un account locale',
  },
  jp: {
    ssoCompleting: 'サインインを完了しています...',
    ssoFailed: 'シングルサインオンに失敗しました',
    ssoHandoffFailed: 'サインインを完了できませんでした。',
    ssoLogin: 'SSO でサインイン',
    ssoLoopBlocked:
      'シングルサインオンがセッションなしで戻ったため、Bichon は再試行を停止しました。下からサインインするか、管理者に OIDC リダイレクト URI の確認を依頼してください。',
    ssoOr: 'または',
    ssoRedirecting: 'ID プロバイダーにリダイレクトしています...',
    ssoUseLocal: 'ローカルアカウントを使用',
  },
  ko: {
    ssoCompleting: '로그인을 완료하는 중...',
    ssoFailed: 'Single Sign-On 실패',
    ssoHandoffFailed: '로그인을 완료할 수 없습니다.',
    ssoLogin: 'SSO로 로그인',
    ssoLoopBlocked:
      'Single Sign-On이 세션 없이 돌아왔기 때문에 Bichon이 재시도를 중단했습니다. 아래에서 로그인하거나 관리자에게 OIDC 리디렉트 URI를 확인하도록 요청하세요.',
    ssoOr: '또는',
    ssoRedirecting: 'ID 공급자로 이동 중...',
    ssoUseLocal: '로컬 계정 사용',
  },
  nl: {
    ssoCompleting: 'Aanmelding voltooien...',
    ssoFailed: 'Single sign-on mislukt',
    ssoHandoffFailed: 'De aanmelding kon niet worden voltooid.',
    ssoLogin: 'Aanmelden met SSO',
    ssoLoopBlocked:
      'Single sign-on kwam terug zonder sessie, daarom probeert Bichon het niet opnieuw. Meld u hieronder aan of vraag een beheerder om de OIDC-redirect-URI te controleren.',
    ssoOr: 'of',
    ssoRedirecting: 'Doorverwijzen naar uw identiteitsprovider...',
    ssoUseLocal: 'Lokaal account gebruiken',
  },
  no: {
    ssoCompleting: 'Fullfører innlogging...',
    ssoFailed: 'Single sign-on mislyktes',
    ssoHandoffFailed: 'Innloggingen kunne ikke fullføres.',
    ssoLogin: 'Logg inn med SSO',
    ssoLoopBlocked:
      'Single sign-on kom tilbake uten en økt, så Bichon sluttet å prøve igjen. Logg inn nedenfor, eller be en administrator om å sjekke OIDC-redirect-URI-en.',
    ssoOr: 'eller',
    ssoRedirecting: 'Videresender til identitetsleverandøren din...',
    ssoUseLocal: 'Bruk en lokal konto',
  },
  pl: {
    ssoCompleting: 'Kończenie logowania...',
    ssoFailed: 'Logowanie jednokrotne nie powiodło się',
    ssoHandoffFailed: 'Nie udało się ukończyć logowania.',
    ssoLogin: 'Zaloguj się przez SSO',
    ssoLoopBlocked:
      'Logowanie jednokrotne wróciło bez sesji, więc Bichon przestał ponawiać próby. Zaloguj się poniżej lub poproś administratora o sprawdzenie adresu URI przekierowania OIDC.',
    ssoOr: 'lub',
    ssoRedirecting: 'Przekierowywanie do dostawcy tożsamości...',
    ssoUseLocal: 'Użyj konta lokalnego',
  },
  pt: {
    ssoCompleting: 'Concluindo o login...',
    ssoFailed: 'Falha no login SSO',
    ssoHandoffFailed: 'Não foi possível concluir o login.',
    ssoLogin: 'Entrar com SSO',
    ssoLoopBlocked:
      'O login SSO retornou sem sessão, por isso o Bichon parou de tentar novamente. Entre abaixo ou peça a um administrador para verificar o URI de redirecionamento OIDC.',
    ssoOr: 'ou',
    ssoRedirecting: 'Redirecionando para seu provedor de identidade...',
    ssoUseLocal: 'Usar uma conta local',
  },
  ru: {
    ssoCompleting: 'Завершение входа...',
    ssoFailed: 'Не удалось выполнить единый вход',
    ssoHandoffFailed: 'Не удалось завершить вход.',
    ssoLogin: 'Войти через SSO',
    ssoLoopBlocked:
      'Единый вход вернулся без сеанса, поэтому Bichon прекратил повторные попытки. Войдите ниже или попросите администратора проверить URI перенаправления OIDC.',
    ssoOr: 'или',
    ssoRedirecting: 'Перенаправление к поставщику удостоверений...',
    ssoUseLocal: 'Использовать локальную учётную запись',
  },
  sv: {
    ssoCompleting: 'Slutför inloggning...',
    ssoFailed: 'Single sign-on misslyckades',
    ssoHandoffFailed: 'Inloggningen kunde inte slutföras.',
    ssoLogin: 'Logga in med SSO',
    ssoLoopBlocked:
      'Single sign-on kom tillbaka utan en session, så Bichon slutade försöka igen. Logga in nedan eller be en administratör att kontrollera OIDC-omdirigerings-URI:n.',
    ssoOr: 'eller',
    ssoRedirecting: 'Omdirigerar till din identitetsleverantör...',
    ssoUseLocal: 'Använd ett lokalt konto',
  },
  zh: {
    ssoCompleting: '正在完成登录...',
    ssoFailed: '单点登录失败',
    ssoHandoffFailed: '无法完成登录。',
    ssoLogin: '使用 SSO 登录',
    ssoLoopBlocked:
      '单点登录返回时未创建会话，因此 Bichon 已停止重试。请在下方登录，或让管理员检查 OIDC 重定向 URI。',
    ssoOr: '或',
    ssoRedirecting: '正在跳转到身份提供商...',
    ssoUseLocal: '使用本地账户',
  },
  'zh-tw': {
    ssoCompleting: '正在完成登入...',
    ssoFailed: '單一登入失敗',
    ssoHandoffFailed: '無法完成登入。',
    ssoLogin: '使用 SSO 登入',
    ssoLoopBlocked:
      '單一登入返回時沒有建立工作階段，因此 Bichon 已停止重試。請在下方登入，或請管理員檢查 OIDC 重新導向 URI。',
    ssoOr: '或',
    ssoRedirecting: '正在轉向身分提供者...',
    ssoUseLocal: '使用本機帳戶',
  },
}

// `deep` so `auth` merges into upstream's `auth` block rather than replacing it,
// and `overwrite: false` so an upstream key always wins. That second flag is what
// keeps this file from silently diverging: `en.ssoLogin` already exists upstream,
// and if upstream ever translates the rest, their wording takes over here too.
Object.entries(SSO_TRANSLATIONS).forEach(([language, strings]) => {
  i18n.addResourceBundle(language, 'translation', { auth: strings }, true, false)
})
