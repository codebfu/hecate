# Feature Repository Management

Use the repository tools to manage signed feature catalogues and installs.

1. Run `list_repo_sources` and `list_repo_features` before making changes.
2. Add only trusted HTTPS sources whose Ed25519 public key was verified out of band.
3. Use `update_repo_source` to change URL, public key, or priority on an existing source.
4. `install_repo_feature` without `version` tracks the newest published release (default).
5. Pass an explicit `version` only when you need a hard pin at install time.
6. Use `pin_repo_feature` / `unpin_repo_feature` to add or remove a pin on an installed feature.
   Unpin resumes tracking latest; it does not remove the feature.
7. Use `install_repo_feature` with an explicit `source_id` when an ID exists in multiple sources.
8. Run `get_repo_status` after install, upgrade, pin, unpin, or uninstall operations.
9. Use `refresh_repo` only to re-fetch catalogue metadata (no upgrades).
10. Use `upgrade_all_repo_features` to upgrade every install that tracks latest; pinned features are skipped.

Removing a source does not force-delete installed features. Uninstall its features first.
The `official` source cannot be removed and its URL is read-only (public key and priority can still be updated).
There are no default feature installs at boot: only the official source is enabled.
