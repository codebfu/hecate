// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { useQuery } from "@tanstack/react-query";
import { apiClient, type AuthStatus } from "../api/client.js";

export function useAuthStatus() {
  const query = useQuery({
    queryKey: ["auth-status"],
    queryFn: () => apiClient.getAuthStatus(),
    retry: false,
  });

  return {
    status: query.data as AuthStatus | undefined,
    isLoading: query.isPending,
    error: query.error,
    refetch: query.refetch,
  };
}
