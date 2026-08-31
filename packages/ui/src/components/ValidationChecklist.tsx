// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ValidationRule } from "../utils/authValidation.js";

interface ValidationChecklistProps {
  rules: ValidationRule[];
  /** When false, hide the checklist until the user has typed something. */
  visible?: boolean;
}

export function ValidationChecklist({ rules, visible = true }: ValidationChecklistProps) {
  if (!visible) {
    return null;
  }

  return (
    <ul className="validation-checklist" aria-live="polite">
      {rules.map((rule) => (
        <li key={rule.id} className={rule.satisfied ? "valid" : "pending"}>
          {rule.label}
        </li>
      ))}
    </ul>
  );
}
