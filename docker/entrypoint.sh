#!/bin/sh
# Copyright (C) 2026 Gaultier HUBERT
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

# hecate-api runs embedded sqlx migrations before binding the HTTP server.
exec /usr/local/bin/hecate-api
