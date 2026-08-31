// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { useQuery } from "@tanstack/react-query";
import { apiClient, type SessionInfo } from "../api/client.js";
import { setCsrfToken } from "../csrf.js";

export function useSession() {
  const query = useQuery({
    queryKey: ["session"],
    queryFn: async () => {
      const session = await apiClient.getSession();
      if (session.csrf_token) {
        setCsrfToken(session.csrf_token);
      }
      return session;
    },
    retry: false,
  });

  // Keep module-level CSRF in sync with cached session (queryFn may not re-run).
  if (query.data?.csrf_token) {
    setCsrfToken(query.data.csrf_token);
  }

  return {
    session: query.data as SessionInfo | undefined,
    isLoading: query.isPending,
    error: query.error,
    refetch: query.refetch,
  };
}
