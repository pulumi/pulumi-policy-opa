# Changelog

## v0.2.0

### New Features

- **Resource metadata in OPA policies**: OPA policies now receive full resource metadata
  including type, URN, name, options (protect, ignoreChanges, customTimeouts, aliases),
  and provider information — not just resource properties. Collision-safe access is available
  via `input.__type`, `input.__urn`, `input.__name`, `input.__options`, `input.__provider`,
  and `input.properties.<key>`. (#24)

- **Stack-level policy support**: New `stack_deny` and `stack_warn` rule prefixes enable
  policies that evaluate the entire stack of resources at once via `AnalyzeStack()`. This
  enables cross-resource checks such as resource count limits, orphan detection, and
  relationship validation. (#25)

- **Policy configuration**: Users can pass custom properties and enforcement level overrides
  to OPA policy packs via `--policy-pack-config` JSON files. Custom config is available in
  Rego as `data.config.<policy_name>.<key>`. Enforcement levels can be overridden to
  advisory, mandatory, or disabled without modifying Rego source. Policy packs can include
  a `config-schema.json` for validation. (#27)

- **OPA annotation metadata extraction**: Policy metadata (title, description, message) is
  now extracted from OPA `METADATA` annotations on Rego rules, populating the previously
  empty Description, Message, and DisplayName fields. Pack-level DisplayName is extracted
  from package-scoped annotations. (#28)

### Improvements

- Use subtests and `t.Parallel()` across all test files for better organization and faster
  test execution. (#29)
- Provider info is always defined (empty map when nil) so policies can safely reference
  provider fields without guarding against undefined.
- Rich aliases: `options.aliases` exposes the full Alias struct; URN-only aliases moved to
  `options.aliasURNs`.
- Guard against panic when OPA rules return non-string values.
- Support for both Rego v0 and v1 syntax.
- Updated documentation and examples for all new features.

## v0.1.0

Initial release.
