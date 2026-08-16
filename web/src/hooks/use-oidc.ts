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

import { useQuery } from '@tanstack/react-query'
import { oidc_config } from '@/api/oidc/api'

/**
 * Whether SSO is available on this server.
 *
 * The endpoint is public, so this also works on the sign-in page where there is
 * no token yet. `isLoading` matters there: the page must not flash the password
 * form before it knows whether to redirect straight to the provider.
 */
export function useOidc() {
  const { data, isLoading } = useQuery({
    queryKey: ['oidc-config'],
    queryFn: oidc_config,
    staleTime: Infinity,
    retry: 1,
  })

  return {
    ssoEnabled: data?.enabled ?? false,
    autoRedirect: data?.auto_redirect ?? false,
    isLoading,
  } as const
}
