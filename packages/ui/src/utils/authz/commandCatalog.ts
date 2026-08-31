// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { CommandDefinitionSummary } from "../../api/client.js";

export interface CommandOption {
  id: string;
  description: string;
  riskLevel?: string;
}

/** Built-in agent command always present before the catalogue loads. */
export const FALLBACK_AGENT_COMMANDS: CommandOption[] = [
  {
    id: "permissions.request",
    description: "Request permanent permission changes (operator approval)",
    riskLevel: "low",
  },
];

export function partitionCommandCatalogue(definitions: CommandDefinitionSummary[]): {
  agentCommands: CommandOption[];
  adminCommands: CommandOption[];
} {
  const agentCommands: CommandOption[] = [];
  const adminCommands: CommandOption[] = [];

  for (const definition of definitions) {
    const option: CommandOption = {
      id: definition.name,
      description: definition.description,
      riskLevel: definition.risk_level,
    };
    if (definition.name.startsWith("admin.")) {
      adminCommands.push(option);
    } else {
      agentCommands.push(option);
    }
  }

  return { agentCommands, adminCommands };
}
