// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it } from "vitest";
import {
  extractApiErrorMessage,
  humanizeApiMessage,
} from "./apiErrorMessage.js";
import {
  isLoginValid,
  isPasswordValid,
  loginValidationRules,
  passwordValidationRules,
} from "./authValidation.js";

describe("authValidation", () => {
  it("matches API login rules", () => {
    expect(isLoginValid("admin")).toBe(true);
    expect(isLoginValid("ab")).toBe(false);
    expect(isLoginValid("bad login")).toBe(false);
    expect(loginValidationRules("admin").every((rule) => rule.satisfied)).toBe(true);
  });

  it("matches API password rules", () => {
    expect(isPasswordValid("short")).toBe(false);
    expect(isPasswordValid("longenoughpass")).toBe(true);
    expect(passwordValidationRules("longenoughpass")[0]?.satisfied).toBe(true);
  });
});

describe("apiErrorMessage", () => {
  it("humanizes known auth validation messages", () => {
    expect(humanizeApiMessage("password too short")).toBe(
      "Password must be at least 12 characters.",
    );
    expect(humanizeApiMessage("invalid login chars")).toBe(
      "Login may only contain letters, numbers, underscores, and hyphens.",
    );
  });

  it("extracts message from API error body", () => {
    expect(
      extractApiErrorMessage(400, {
        error: "bad_request",
        message: "password too short",
      }),
    ).toBe("Password must be at least 12 characters.");
  });
});
