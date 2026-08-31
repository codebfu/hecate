// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

/** Matches `validate_login` / `validate_password` in crates/api/src/routes/auth.rs */

export const LOGIN_MIN_LENGTH = 3;
export const LOGIN_MAX_LENGTH = 32;
export const PASSWORD_MIN_LENGTH = 12;

const LOGIN_PATTERN = /^[A-Za-z0-9_-]+$/;

export interface ValidationRule {
  id: string;
  label: string;
  satisfied: boolean;
}

export function loginValidationRules(login: string): ValidationRule[] {
  return [
    {
      id: "login-length",
      label: `${LOGIN_MIN_LENGTH}–${LOGIN_MAX_LENGTH} characters`,
      satisfied: login.length >= LOGIN_MIN_LENGTH && login.length <= LOGIN_MAX_LENGTH,
    },
    {
      id: "login-chars",
      label: "Letters, numbers, underscores, and hyphens only",
      satisfied: login.length === 0 || LOGIN_PATTERN.test(login),
    },
  ];
}

export function passwordValidationRules(password: string): ValidationRule[] {
  return [
    {
      id: "password-length",
      label: `At least ${PASSWORD_MIN_LENGTH} characters`,
      satisfied: password.length >= PASSWORD_MIN_LENGTH,
    },
  ];
}

export function isLoginValid(login: string): boolean {
  return login.length > 0 && loginValidationRules(login).every((rule) => rule.satisfied);
}

export function isPasswordValid(password: string): boolean {
  return password.length > 0 && passwordValidationRules(password).every((rule) => rule.satisfied);
}

export function firstLoginValidationError(login: string): string | null {
  const rules = loginValidationRules(login);
  if (login.length === 0) {
    return "Login is required.";
  }
  if (!rules[0]!.satisfied) {
    return "Login must be 3–32 characters.";
  }
  if (!rules[1]!.satisfied) {
    return "Login may only contain letters, numbers, underscores, and hyphens.";
  }
  return null;
}

export function firstPasswordValidationError(password: string): string | null {
  if (password.length === 0) {
    return "Password is required.";
  }
  if (!isPasswordValid(password)) {
    return "Password must be at least 12 characters.";
  }
  return null;
}
