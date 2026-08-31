//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

#![no_main]

use libfuzzer_sys::fuzz_target;
use hecate_protocol::policy::{check_cwd_policy, check_shell_policy, validate_argv};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let argv: Vec<String> = text.split('\0').map(str::to_string).collect();
    if !argv.is_empty() {
        let _ = validate_argv(&argv);
        let allowed = vec!["/usr/bin/uptime".into(), "*".into()];
        let _ = check_shell_policy(&argv, &allowed);
    }

    let _ = check_cwd_policy(text, &["/tmp".into(), "/var".into()]);
    let _ = check_cwd_policy(text, &[]);
});
