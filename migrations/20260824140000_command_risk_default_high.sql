-- Copyright (C) 2026 Gaultier HUBERT
-- SPDX-License-Identifier: GPL-3.0-or-later

-- Deny-by-default for newly registered commands without an explicit risk_level.
ALTER TABLE command_definitions
  ALTER COLUMN risk_level SET DEFAULT 'high';
